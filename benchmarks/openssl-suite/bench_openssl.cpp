#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

static void ossl_check(bool ok, const char* what) {
    if (!ok) throw std::runtime_error(std::string("OpenSSL failure: ") + what);
}

template <class T, void(*F)(T*)>
using ossl_ptr = std::unique_ptr<T, decltype(F)>;

static double median(std::vector<double> v) {
    if (v.empty()) return NAN;
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return (n & 1) ? v[n/2] : 0.5 * (v[n/2 - 1] + v[n/2]);
}

struct BenchConfig {
    int runs = 21;
    int samples_per_run = 31;
    double target_sample_us = 2000.0;
    size_t max_batch = 1u << 20;
};

struct BenchResult {
    std::string primitive;
    std::string notes;
    size_t batch = 1;
    std::vector<double> run_medians_us;
};

static double batch_us(const std::function<void()>& fn, size_t n) {
    auto t0 = Clock::now();
    for (size_t i = 0; i < n; ++i) fn();
    auto t1 = Clock::now();
    return std::chrono::duration<double, std::micro>(t1 - t0).count();
}

static BenchResult bench(const std::string& name,
                         const std::string& notes,
                         const std::function<void()>& fn,
                         BenchConfig cfg = {}) {
    // Warm-up.
    for (int i = 0; i < 64; ++i) fn();

    // Automatically choose a batch size so clock-call overhead is negligible
    // for sub-microsecond primitives.
    size_t batch = 1;
    double elapsed = batch_us(fn, batch);
    while (elapsed < cfg.target_sample_us && batch < cfg.max_batch) {
        batch *= 2;
        elapsed = batch_us(fn, batch);
    }

    const double approx_per_call = elapsed / static_cast<double>(batch);
    if (approx_per_call > 5000.0) {
        cfg.runs = std::min(cfg.runs, 11);
        cfg.samples_per_run = std::min(cfg.samples_per_run, 11);
    } else if (approx_per_call > 500.0) {
        cfg.runs = std::min(cfg.runs, 15);
        cfg.samples_per_run = std::min(cfg.samples_per_run, 15);
    }

    BenchResult out{name, notes, batch, {}};
    out.run_medians_us.reserve(cfg.runs);

    for (int r = 0; r < cfg.runs; ++r) {
        std::vector<double> samples;
        samples.reserve(cfg.samples_per_run);
        for (int s = 0; s < cfg.samples_per_run; ++s) {
            samples.push_back(batch_us(fn, batch) / static_cast<double>(batch));
        }
        out.run_medians_us.push_back(median(samples));
    }
    return out;
}

static void write_runs_csv(const std::string& path,
                           const std::vector<BenchResult>& results) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot open output: " + path);
    f << "primitive,run,median_us,batch_size,notes\n";
    for (const auto& r : results) {
        for (size_t i = 0; i < r.run_medians_us.size(); ++i) {
            std::string notes = r.notes;
            std::replace(notes.begin(), notes.end(), '"', '\'');
            f << r.primitive << ',' << (i + 1) << ','
              << std::fixed << std::setprecision(9)
              << r.run_medians_us[i] << ',' << r.batch << ",\""
              << notes << "\"\n";
        }
    }
}

static BIGNUM* rand_scalar(const BIGNUM* order) {
    BIGNUM* x = BN_new();
    ossl_check(x != nullptr, "BN_new");
    do {
        ossl_check(BN_priv_rand_range(x, order) == 1, "BN_priv_rand_range");
    } while (BN_is_zero(x));
    return x;
}

static EVP_PKEY* make_rsa3072() {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    ossl_check(kctx != nullptr, "EVP_PKEY_CTX_new_from_name RSA");
    ossl_check(EVP_PKEY_keygen_init(kctx) > 0, "EVP_PKEY_keygen_init");
    ossl_check(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072) > 0, "set_rsa_bits");
    EVP_PKEY* pkey = nullptr;
    ossl_check(EVP_PKEY_generate(kctx, &pkey) > 0, "EVP_PKEY_generate");
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

static void configure_rsa_oaep(EVP_PKEY_CTX* ctx) {
    ossl_check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0,
               "RSA OAEP padding");
    ossl_check(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0,
               "RSA OAEP md");
    ossl_check(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0,
               "RSA MGF1 md");
}

int main(int argc, char** argv) {
    const std::string out_path = (argc > 1) ? argv[1] : "runs_openssl.csv";
    std::vector<BenchResult> R;

    std::array<unsigned char, 64> msg64{};
    std::array<unsigned char, 128> msg128{};
    std::array<unsigned char, 32> key32{}, salt32{}, digest32{};
    std::array<unsigned char, 16> iv16{};
    ossl_check(RAND_bytes(msg64.data(), msg64.size()) == 1, "RAND msg64");
    ossl_check(RAND_bytes(msg128.data(), msg128.size()) == 1, "RAND msg128");
    ossl_check(RAND_bytes(key32.data(), key32.size()) == 1, "RAND key");
    ossl_check(RAND_bytes(salt32.data(), salt32.size()) == 1, "RAND salt");
    ossl_check(RAND_bytes(iv16.data(), iv16.size()) == 1, "RAND iv");
    SHA256(msg64.data(), msg64.size(), digest32.data());

    // T_H
    std::array<unsigned char, 32> sha_out{};
    R.push_back(bench("T_H_SHA256_64B",
                      "SHA-256 over a 64-byte input",
                      [&](){ SHA256(msg64.data(), msg64.size(), sha_out.data()); }));

    // P-256 common group.
    ossl_ptr<EC_GROUP, EC_GROUP_free> group(
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
    ossl_check(group != nullptr, "EC_GROUP P-256");
    ossl_ptr<BN_CTX, BN_CTX_free> bnctx(BN_CTX_new(), BN_CTX_free);
    ossl_check(bnctx != nullptr, "BN_CTX_new");
    ossl_ptr<BIGNUM, BN_free> order(BN_new(), BN_free);
    ossl_check(EC_GROUP_get_order(group.get(), order.get(), bnctx.get()) == 1,
               "get EC order");

    ossl_ptr<BIGNUM, BN_free> q_scalar(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> a_scalar(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> b_scalar(rand_scalar(order.get()), BN_free);
    ossl_ptr<EC_POINT, EC_POINT_free> Q(EC_POINT_new(group.get()), EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> Rpt(EC_POINT_new(group.get()), EC_POINT_free);
    ossl_check(EC_POINT_mul(group.get(), Q.get(), q_scalar.get(),
                            nullptr, nullptr, bnctx.get()) == 1, "Q=qG");

    // T_SM: deliberately use ordinary variable-base multiplication for the
    // main normalized comparison; fixed-base-specific acceleration is not
    // given only to the proposed scheme.
    R.push_back(bench("T_SM_P256",
                      "Ordinary P-256 variable-base scalar multiplication kQ; scalar and Q pre-generated",
                      [&](){
                          ossl_check(EC_POINT_mul(group.get(), Rpt.get(), nullptr,
                                                  Q.get(), a_scalar.get(),
                                                  bnctx.get()) == 1,
                                     "EC_POINT_mul variable");
                      }));

    // T_MSM: two-term MSM aG+bQ, matching equations such as mP+gammaY.
    R.push_back(bench("T_MSM2_P256",
                      "Two-term P-256 multi-scalar multiplication aG+bQ",
                      [&](){
                          ossl_check(EC_POINT_mul(group.get(), Rpt.get(),
                                                  a_scalar.get(), Q.get(),
                                                  b_scalar.get(), bnctx.get()) == 1,
                                     "EC_POINT_mul MSM2");
                      }));

    // ECDSA P-256, prehashed.
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    ossl_check(eckey != nullptr, "EC_KEY_new");
    ossl_check(EC_KEY_generate_key(eckey) == 1, "EC_KEY_generate_key");
    ECDSA_SIG* fixed_sig =
        ECDSA_do_sign(digest32.data(), digest32.size(), eckey);
    ossl_check(fixed_sig != nullptr, "ECDSA_do_sign fixed");

    R.push_back(bench("T_SG_ECDSA_P256_PREHASHED",
                      "ECDSA P-256 signing of a precomputed SHA-256 digest; key generation excluded",
                      [&](){
                          ECDSA_SIG* s =
                              ECDSA_do_sign(digest32.data(), digest32.size(), eckey);
                          ossl_check(s != nullptr, "ECDSA sign");
                          ECDSA_SIG_free(s);
                      }));

    R.push_back(bench("T_SV_ECDSA_P256_PREHASHED",
                      "ECDSA P-256 verification of a precomputed SHA-256 digest; signature pre-generated",
                      [&](){
                          ossl_check(ECDSA_do_verify(digest32.data(),
                                                     digest32.size(),
                                                     fixed_sig, eckey) == 1,
                                     "ECDSA verify");
                      }));

    // AES-256-CBC over 128 B. Padding is disabled so the payload size is exact.
    std::array<unsigned char, 160> aes_ct{}, aes_pt{};
    int outl1=0, outl2=0;
    {
        EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
        ossl_check(c != nullptr, "AES pre ctx");
        ossl_check(EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), nullptr,
                                      key32.data(), iv16.data()) == 1,
                   "AES pre init");
        EVP_CIPHER_CTX_set_padding(c, 0);
        ossl_check(EVP_EncryptUpdate(c, aes_ct.data(), &outl1,
                                     msg128.data(), msg128.size()) == 1,
                   "AES pre update");
        ossl_check(EVP_EncryptFinal_ex(c, aes_ct.data()+outl1, &outl2) == 1,
                   "AES pre final");
        EVP_CIPHER_CTX_free(c);
    }

    R.push_back(bench("T_SE_AES256_CBC_128B",
                      "AES-256-CBC encryption of 128 bytes; includes context init/update/final",
                      [&](){
                          EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
                          ossl_check(c != nullptr, "AES enc ctx");
                          int l1=0,l2=0;
                          ossl_check(EVP_EncryptInit_ex(c, EVP_aes_256_cbc(),
                                                       nullptr, key32.data(),
                                                       iv16.data()) == 1,
                                     "AES enc init");
                          EVP_CIPHER_CTX_set_padding(c, 0);
                          ossl_check(EVP_EncryptUpdate(c, aes_ct.data(), &l1,
                                                       msg128.data(),
                                                       msg128.size()) == 1,
                                     "AES enc update");
                          ossl_check(EVP_EncryptFinal_ex(c, aes_ct.data()+l1,
                                                        &l2) == 1,
                                     "AES enc final");
                          EVP_CIPHER_CTX_free(c);
                      }));

    R.push_back(bench("T_SD_AES256_CBC_128B",
                      "AES-256-CBC decryption of 128 bytes; includes context init/update/final",
                      [&](){
                          EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
                          ossl_check(c != nullptr, "AES dec ctx");
                          int l1=0,l2=0;
                          ossl_check(EVP_DecryptInit_ex(c, EVP_aes_256_cbc(),
                                                       nullptr, key32.data(),
                                                       iv16.data()) == 1,
                                     "AES dec init");
                          EVP_CIPHER_CTX_set_padding(c, 0);
                          ossl_check(EVP_DecryptUpdate(c, aes_pt.data(), &l1,
                                                       aes_ct.data(),
                                                       msg128.size()) == 1,
                                     "AES dec update");
                          ossl_check(EVP_DecryptFinal_ex(c, aes_pt.data()+l1,
                                                        &l2) == 1,
                                     "AES dec final");
                          EVP_CIPHER_CTX_free(c);
                      }));

    // HMAC-based KDF, HKDF, and MAC.
    std::array<unsigned char, 32> hmac_out{}, expected_mac{};
    unsigned int hlen=0;
    HMAC(EVP_sha256(), key32.data(), key32.size(),
         msg64.data(), msg64.size(), expected_mac.data(), &hlen);

    R.push_back(bench("T_KDF_HMAC_SHA256",
                      "HMAC-SHA-256-based credential KDF core over a fixed encoded context",
                      [&](){
                          unsigned int n=0;
                          HMAC(EVP_sha256(), key32.data(), key32.size(),
                               msg64.data(), msg64.size(),
                               hmac_out.data(), &n);
                      }));

    R.push_back(bench("T_HKEXT_SHA256",
                      "HKDF-Extract modeled as HMAC-SHA-256(salt, IKM)",
                      [&](){
                          unsigned int n=0;
                          HMAC(EVP_sha256(), salt32.data(), salt32.size(),
                               msg64.data(), msg64.size(),
                               hmac_out.data(), &n);
                      }));

    std::array<unsigned char, 33> hk_info{};
    std::memcpy(hk_info.data(), msg64.data(), 32);
    hk_info[32] = 0x01;

    R.push_back(bench("T_HKEXP_SHA256_32B",
                      "HKDF-Expand for one 32-byte output block",
                      [&](){
                          unsigned int n=0;
                          HMAC(EVP_sha256(), key32.data(), key32.size(),
                               hk_info.data(), hk_info.size(),
                               hmac_out.data(), &n);
                      }));

    R.push_back(bench("T_MACG_HMAC_SHA256_64B",
                      "HMAC-SHA-256 tag generation over 64 bytes",
                      [&](){
                          unsigned int n=0;
                          HMAC(EVP_sha256(), key32.data(), key32.size(),
                               msg64.data(), msg64.size(),
                               hmac_out.data(), &n);
                      }));

    R.push_back(bench("T_MACV_HMAC_SHA256_64B",
                      "HMAC-SHA-256 recomputation plus constant-time tag comparison",
                      [&](){
                          unsigned int n=0;
                          HMAC(EVP_sha256(), key32.data(), key32.size(),
                               msg64.data(), msg64.size(),
                               hmac_out.data(), &n);
                          volatile int eq =
                              CRYPTO_memcmp(hmac_out.data(),
                                           expected_mac.data(), 32);
                          (void)eq;
                      }));

    // Full unbiased hash-to-scalar H2S for the P-256 instantiation.
    //
    // For input x and counter ctr = 0,1,...:
    //   h   = SHA256("H2S" || I2OSP(ctr,4) || x)
    //   u   = OS2IP(h)
    // accept the first u satisfying 1 <= u < q.
    //
    // Under the random-oracle model for SHA-256, rejection sampling makes
    // the accepted output exactly uniform over Z_q^*.
    //
    // For the P-256 group order, rejection occurs with probability about
    // 2^-32, so almost every invocation performs exactly one SHA-256.
    std::array<unsigned char, 32> h2s_in{};
    ossl_check(RAND_bytes(h2s_in.data(), h2s_in.size()) == 1,
               "RAND h2s input");
    ossl_ptr<BIGNUM, BN_free> h2s_out(BN_new(), BN_free);

    auto h2s_unbiased_once = [&](){
        std::array<unsigned char, 39> buf{};
        std::array<unsigned char, 32> digest{};

        // Domain-separation tag.
        buf[0] = static_cast<unsigned char>('H');
        buf[1] = static_cast<unsigned char>('2');
        buf[2] = static_cast<unsigned char>('S');
        std::memcpy(buf.data() + 7, h2s_in.data(), h2s_in.size());

        for (uint32_t ctr = 0; ; ++ctr) {
            // I2OSP(ctr, 4), big endian.
            buf[3] = static_cast<unsigned char>((ctr >> 24) & 0xff);
            buf[4] = static_cast<unsigned char>((ctr >> 16) & 0xff);
            buf[5] = static_cast<unsigned char>((ctr >>  8) & 0xff);
            buf[6] = static_cast<unsigned char>( ctr        & 0xff);

            SHA256(buf.data(), buf.size(), digest.data());
            ossl_check(BN_bin2bn(digest.data(), digest.size(),
                                 h2s_out.get()) != nullptr,
                       "H2S OS2IP");

            if (!BN_is_zero(h2s_out.get()) &&
                BN_cmp(h2s_out.get(), order.get()) < 0) {
                break;
            }
        }
    };

    // Correctness/range sanity check before timing.
    h2s_unbiased_once();
    ossl_check(!BN_is_zero(h2s_out.get()) &&
               BN_cmp(h2s_out.get(), order.get()) < 0,
               "H2S output range");

    R.push_back(bench("T_H2S_UNBIASED_P256",
                      "Complete unbiased P-256 hash-to-scalar: SHA-256 domain-separated rejection sampling into Z_q^*",
                      h2s_unbiased_once));

    // Shamir 3-of-5 over the P-256 scalar field.
    ossl_ptr<BIGNUM, BN_free> secret(rand_scalar(order.get()), BN_free);
    std::array<ossl_ptr<BIGNUM, BN_free>,5> sx = {
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free)
    };
    std::array<ossl_ptr<BIGNUM, BN_free>,5> sy = {
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free),
        ossl_ptr<BIGNUM, BN_free>(BN_new(), BN_free)
    };
    for (int i=0;i<5;++i) BN_set_word(sx[i].get(), i+1);

    auto shamir_split_once = [&](){
        ossl_ptr<BIGNUM, BN_free> c1(rand_scalar(order.get()), BN_free);
        ossl_ptr<BIGNUM, BN_free> c2(rand_scalar(order.get()), BN_free);
        ossl_ptr<BIGNUM, BN_free> x2(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> t1(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> t2(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> tmp(BN_new(), BN_free);

        for (int i=0;i<5;++i) {
            ossl_check(BN_mod_sqr(x2.get(), sx[i].get(),
                                  order.get(), bnctx.get()) == 1,
                       "Shamir x2");
            ossl_check(BN_mod_mul(t1.get(), c1.get(), sx[i].get(),
                                  order.get(), bnctx.get()) == 1,
                       "Shamir c1x");
            ossl_check(BN_mod_mul(t2.get(), c2.get(), x2.get(),
                                  order.get(), bnctx.get()) == 1,
                       "Shamir c2x2");
            ossl_check(BN_mod_add(tmp.get(), secret.get(), t1.get(),
                                  order.get(), bnctx.get()) == 1,
                       "Shamir add1");
            ossl_check(BN_mod_add(sy[i].get(), tmp.get(), t2.get(),
                                  order.get(), bnctx.get()) == 1,
                       "Shamir add2");
        }
    };
    shamir_split_once();

    R.push_back(bench("T_SS_SHAMIR_3OF5_P256",
                      "Shamir 3-of-5 sharing over P-256 scalar field; fresh random polynomial coefficients included",
                      shamir_split_once));

    auto shamir_recover_once = [&](){
        ossl_ptr<BIGNUM, BN_free> acc(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> num(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> den(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> negx(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> diff(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> inv(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> lam(BN_new(), BN_free);
        ossl_ptr<BIGNUM, BN_free> term(BN_new(), BN_free);
        BN_zero(acc.get());

        for (int i=0;i<3;++i) {
            BN_one(num.get());
            BN_one(den.get());
            for (int j=0;j<3;++j) if (i != j) {
                BN_zero(negx.get());
                ossl_check(BN_mod_sub(negx.get(), negx.get(), sx[j].get(),
                                      order.get(), bnctx.get()) == 1,
                           "Lagrange -xj");
                ossl_check(BN_mod_mul(num.get(), num.get(), negx.get(),
                                      order.get(), bnctx.get()) == 1,
                           "Lagrange num");
                ossl_check(BN_mod_sub(diff.get(), sx[i].get(), sx[j].get(),
                                      order.get(), bnctx.get()) == 1,
                           "Lagrange diff");
                ossl_check(BN_mod_mul(den.get(), den.get(), diff.get(),
                                      order.get(), bnctx.get()) == 1,
                           "Lagrange den");
            }
            ossl_check(BN_mod_inverse(inv.get(), den.get(),
                                      order.get(), bnctx.get()) != nullptr,
                       "Lagrange inverse");
            ossl_check(BN_mod_mul(lam.get(), num.get(), inv.get(),
                                  order.get(), bnctx.get()) == 1,
                       "Lagrange lambda");
            ossl_check(BN_mod_mul(term.get(), sy[i].get(), lam.get(),
                                  order.get(), bnctx.get()) == 1,
                       "Lagrange term");
            ossl_check(BN_mod_add(acc.get(), acc.get(), term.get(),
                                  order.get(), bnctx.get()) == 1,
                       "Lagrange acc");
        }
        ossl_check(BN_cmp(acc.get(), secret.get()) == 0,
                   "Shamir recovery correctness");
    };

    R.push_back(bench("T_SR_SHAMIR_3OF5_P256",
                      "Shamir reconstruction from three shares using Lagrange interpolation at x=0",
                      shamir_recover_once));

    // Pedersen commitment C=mG+rH.
    ossl_ptr<BIGNUM, BN_free> h_scalar(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> m_scalar(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> r_scalar(rand_scalar(order.get()), BN_free);
    ossl_ptr<EC_POINT, EC_POINT_free> Hpt(EC_POINT_new(group.get()),
                                          EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> Cpt(EC_POINT_new(group.get()),
                                          EC_POINT_free);
    ossl_check(EC_POINT_mul(group.get(), Hpt.get(), h_scalar.get(),
                            nullptr, nullptr, bnctx.get()) == 1,
               "H=hG");

    R.push_back(bench("T_COM_PEDERSEN_P256",
                      "Pedersen commitment C=mG+rH over P-256; H, m and r pre-generated",
                      [&](){
                          ossl_check(EC_POINT_mul(group.get(), Cpt.get(),
                                                  m_scalar.get(), Hpt.get(),
                                                  r_scalar.get(), bnctx.get()) == 1,
                                     "Pedersen commit");
                      }));

    // Normalized SanSig.Sanit: CH(m,r)=mG+rY, Y=xG.
    // Collision r'=r+(m-m')/x mod q.
    ossl_ptr<BIGNUM, BN_free> ch_x(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> ch_m(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> ch_mp(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> ch_r(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> ch_rp(BN_new(), BN_free);
    ossl_ptr<BIGNUM, BN_free> ch_inv(BN_new(), BN_free);
    ossl_ptr<BIGNUM, BN_free> ch_diff(BN_new(), BN_free);
    ossl_ptr<BIGNUM, BN_free> ch_tmp(BN_new(), BN_free);
    ossl_ptr<EC_POINT, EC_POINT_free> ch_Y(EC_POINT_new(group.get()),
                                           EC_POINT_free);
    ossl_check(EC_POINT_mul(group.get(), ch_Y.get(), ch_x.get(),
                            nullptr, nullptr, bnctx.get()) == 1,
               "CH Y=xG");

    auto ch_collision_once = [&](){
        ossl_check(BN_mod_inverse(ch_inv.get(), ch_x.get(),
                                  order.get(), bnctx.get()) != nullptr,
                   "CH inv x");
        ossl_check(BN_mod_sub(ch_diff.get(), ch_m.get(), ch_mp.get(),
                              order.get(), bnctx.get()) == 1,
                   "CH diff");
        ossl_check(BN_mod_mul(ch_tmp.get(), ch_diff.get(), ch_inv.get(),
                              order.get(), bnctx.get()) == 1,
                   "CH div");
        ossl_check(BN_mod_add(ch_rp.get(), ch_r.get(), ch_tmp.get(),
                              order.get(), bnctx.get()) == 1,
                   "CH rprime");
    };
    ch_collision_once();

    R.push_back(bench("T_SAN_CH_COLLISION_P256",
                      "Normalized SanSig sanitization: P-256 chameleon-hash collision generation including modular inversion",
                      ch_collision_once));

    // Normalized SanSig.Verify: collision validation + SHA-256 + ECDSA verify.
    ossl_ptr<EC_POINT, EC_POINT_free> ch_C1(EC_POINT_new(group.get()),
                                            EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> ch_C2(EC_POINT_new(group.get()),
                                            EC_POINT_free);
    std::array<unsigned char,32> san_digest{};
    SHA256(msg64.data(), msg64.size(), san_digest.data());
    ECDSA_SIG* san_sig =
        ECDSA_do_sign(san_digest.data(), san_digest.size(), eckey);
    ossl_check(san_sig != nullptr, "SanSig ECDSA signature");

    R.push_back(bench("T_SANV_CH_ECDSA_P256",
                      "Normalized SanSig verification: P-256 CH collision validation + SHA-256 + ECDSA-P256 verification",
                      [&](){
                          ossl_check(EC_POINT_mul(group.get(), ch_C1.get(),
                                                  ch_m.get(), ch_Y.get(),
                                                  ch_r.get(), bnctx.get()) == 1,
                                     "CH C1");
                          ossl_check(EC_POINT_mul(group.get(), ch_C2.get(),
                                                  ch_mp.get(), ch_Y.get(),
                                                  ch_rp.get(), bnctx.get()) == 1,
                                     "CH C2");
                          ossl_check(EC_POINT_cmp(group.get(), ch_C1.get(),
                                                  ch_C2.get(), bnctx.get()) == 0,
                                     "CH compare");
                          SHA256(msg64.data(), msg64.size(), san_digest.data());
                          ossl_check(ECDSA_do_verify(san_digest.data(),
                                                     san_digest.size(),
                                                     san_sig, eckey) == 1,
                                     "SanSig ECDSA verify");
                      }));

    // MVNO-HO public-key normalization: RSA-3072 KGen and OAEP-SHA256.
    R.push_back(bench("T_KG_RSA3072",
                      "RSA-3072 key-pair generation; explicit normalization of MVNO-HO KGen",
                      [&](){
                          EVP_PKEY* p = make_rsa3072();
                          EVP_PKEY_free(p);
                      },
                      BenchConfig{11,11,1000.0,64}));

    ossl_ptr<EVP_PKEY, EVP_PKEY_free> rsa(make_rsa3072(), EVP_PKEY_free);
    std::array<unsigned char,384> rsa_ct{};
    size_t rsa_ct_len = rsa_ct.size();
    {
        EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(rsa.get(), nullptr);
        ossl_check(c != nullptr, "RSA pre enc ctx");
        ossl_check(EVP_PKEY_encrypt_init(c) > 0, "RSA pre enc init");
        configure_rsa_oaep(c);
        rsa_ct_len = rsa_ct.size();
        ossl_check(EVP_PKEY_encrypt(c, rsa_ct.data(), &rsa_ct_len,
                                    msg128.data(), msg128.size()) > 0,
                   "RSA pre encrypt");
        EVP_PKEY_CTX_free(c);
    }

    R.push_back(bench("T_PKE_RSA3072_OAEP_SHA256_128B",
                      "RSA-3072 OAEP-SHA256 encryption of a 128-byte plaintext; key generation excluded",
                      [&](){
                          EVP_PKEY_CTX* c =
                              EVP_PKEY_CTX_new(rsa.get(), nullptr);
                          ossl_check(c != nullptr, "RSA enc ctx");
                          ossl_check(EVP_PKEY_encrypt_init(c) > 0,
                                     "RSA enc init");
                          configure_rsa_oaep(c);
                          size_t n = rsa_ct.size();
                          ossl_check(EVP_PKEY_encrypt(c, rsa_ct.data(), &n,
                                                      msg128.data(),
                                                      msg128.size()) > 0,
                                     "RSA encrypt");
                          EVP_PKEY_CTX_free(c);
                      }));

    R.push_back(bench("T_PKD_RSA3072_OAEP_SHA256_128B",
                      "RSA-3072 OAEP-SHA256 decryption of a ciphertext carrying a 128-byte plaintext; key generation excluded",
                      [&](){
                          EVP_PKEY_CTX* c =
                              EVP_PKEY_CTX_new(rsa.get(), nullptr);
                          ossl_check(c != nullptr, "RSA dec ctx");
                          ossl_check(EVP_PKEY_decrypt_init(c) > 0,
                                     "RSA dec init");
                          configure_rsa_oaep(c);
                          std::array<unsigned char,384> pt{};
                          size_t n = pt.size();
                          ossl_check(EVP_PKEY_decrypt(c, pt.data(), &n,
                                                      rsa_ct.data(),
                                                      rsa_ct_len) > 0,
                                     "RSA decrypt");
                          EVP_PKEY_CTX_free(c);
                      }));

    // P-256 EC-ElGamal; message-to-point mapping excluded.
    ossl_ptr<BIGNUM, BN_free> eg_x(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> eg_m(rand_scalar(order.get()), BN_free);
    ossl_ptr<BIGNUM, BN_free> eg_k(BN_new(), BN_free);
    ossl_ptr<EC_POINT, EC_POINT_free> eg_Y(EC_POINT_new(group.get()),
                                           EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> eg_M(EC_POINT_new(group.get()),
                                           EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> eg_C1(EC_POINT_new(group.get()),
                                            EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> eg_C2(EC_POINT_new(group.get()),
                                            EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> eg_tmp(EC_POINT_new(group.get()),
                                             EC_POINT_free);
    ossl_ptr<EC_POINT, EC_POINT_free> eg_rec(EC_POINT_new(group.get()),
                                             EC_POINT_free);

    ossl_check(EC_POINT_mul(group.get(), eg_Y.get(), eg_x.get(),
                            nullptr, nullptr, bnctx.get()) == 1,
               "ElGamal Y");
    ossl_check(EC_POINT_mul(group.get(), eg_M.get(), eg_m.get(),
                            nullptr, nullptr, bnctx.get()) == 1,
               "ElGamal M");

    auto eg_encrypt_once = [&](){
        do {
            ossl_check(BN_priv_rand_range(eg_k.get(), order.get()) == 1,
                       "ElGamal k");
        } while (BN_is_zero(eg_k.get()));

        ossl_check(EC_POINT_mul(group.get(), eg_C1.get(), eg_k.get(),
                                nullptr, nullptr, bnctx.get()) == 1,
                   "ElGamal C1");
        ossl_check(EC_POINT_mul(group.get(), eg_tmp.get(), nullptr,
                                eg_Y.get(), eg_k.get(), bnctx.get()) == 1,
                   "ElGamal kY");
        ossl_check(EC_POINT_add(group.get(), eg_C2.get(), eg_M.get(),
                                eg_tmp.get(), bnctx.get()) == 1,
                   "ElGamal C2");
    };
    eg_encrypt_once();

    R.push_back(bench("T_EGE_ECELGAMAL_P256",
                      "P-256 EC-ElGamal encryption C1=kG,C2=M+kY; fresh k included; M pre-encoded",
                      eg_encrypt_once));

    R.push_back(bench("T_EGD_ECELGAMAL_P256",
                      "P-256 EC-ElGamal decryption M=C2-xC1; message decoding excluded",
                      [&](){
                          ossl_check(EC_POINT_mul(group.get(), eg_tmp.get(),
                                                  nullptr, eg_C1.get(),
                                                  eg_x.get(), bnctx.get()) == 1,
                                     "ElGamal xC1");
                          ossl_check(EC_POINT_invert(group.get(), eg_tmp.get(),
                                                     bnctx.get()) == 1,
                                     "ElGamal invert");
                          ossl_check(EC_POINT_add(group.get(), eg_rec.get(),
                                                  eg_C2.get(), eg_tmp.get(),
                                                  bnctx.get()) == 1,
                                     "ElGamal recover");
                      }));

    // TC3A modular exponentiation.
    ossl_ptr<BIGNUM, BN_free> modp(BN_new(), BN_free);
    ossl_ptr<BIGNUM, BN_free> base(BN_new(), BN_free);
    ossl_ptr<BIGNUM, BN_free> exp(BN_new(), BN_free);
    ossl_ptr<BIGNUM, BN_free> modp_out(BN_new(), BN_free);
    ossl_check(BN_get_rfc3526_prime_3072(modp.get()) != nullptr,
               "RFC3526 prime3072");
    BN_set_word(base.get(), 2);
    ossl_check(BN_priv_rand(exp.get(), 256, BN_RAND_TOP_ONE,
                            BN_RAND_BOTTOM_ANY) == 1,
               "256-bit exponent");
    BN_set_flags(exp.get(), BN_FLG_CONSTTIME);

    R.push_back(bench("T_MEXP_MODP3072_EXP256",
                      "RFC3526 Group 15 3072-bit modular exponentiation with a 256-bit constant-time exponent",
                      [&](){
                          ossl_check(BN_mod_exp_mont_consttime(
                                         modp_out.get(), base.get(), exp.get(),
                                         modp.get(), bnctx.get(), nullptr) == 1,
                                     "BN_mod_exp_mont_consttime");
                      }));

    write_runs_csv(out_path, R);
    std::cerr << "Wrote " << out_path
              << " with " << R.size() << " primitives.\n";

    ECDSA_SIG_free(fixed_sig);
    ECDSA_SIG_free(san_sig);
    EC_KEY_free(eckey);
    return 0;
}
