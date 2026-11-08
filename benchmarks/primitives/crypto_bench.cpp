#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <pbc.h>
#include <mcl/bn_c384_256.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>
using Clock = std::chrono::steady_clock;
constexpr int SAMPLES = 31;
constexpr size_t HASH_BYTES = 64;
constexpr size_t AES_BYTES = 128;
[[noreturn]] static void die(const std::string& s){ throw std::runtime_error(s); }
static constexpr const char* PBC_PARAM_PATH = "params/a_160_512.param";
static void ensure_type_a_param() {
    namespace fs = std::filesystem;
    const fs::path p(PBC_PARAM_PATH);
    if (fs::exists(p) && fs::is_regular_file(p) && fs::file_size(p) > 0) {
        return;
    }
    if (p.has_parent_path()) {
        fs::create_directories(p.parent_path());
    }
    pbc_param_t param;
    pbc_param_init_a_gen(param, 160, 512);  // rbits=160, qbits=512
    FILE* fp = std::fopen(PBC_PARAM_PATH, "w");
    if (!fp) {
        pbc_param_clear(param);
        die("cannot create PBC parameter file: " + std::string(PBC_PARAM_PATH));
    }
    pbc_param_out_str(fp, param);
    std::fclose(fp);
    pbc_param_clear(param);
}
struct Stats {
    double mean, median, sd, minv, p95;
    int samples, inner;
};
static Stats summarize(std::vector<double> x, int inner) {
    std::sort(x.begin(), x.end());
    double mean = std::accumulate(x.begin(), x.end(), 0.0) / x.size();
    double ss = 0;
    for(double v:x) ss += (v-mean)*(v-mean);
    size_t p = std::min(x.size()-1, (size_t)std::ceil(0.95*x.size())-1);
    return {mean, x[x.size()/2], std::sqrt(ss/x.size()), x.front(), x[p],
            (int)x.size(), inner};
}
template<class F>
static Stats bench(F fn, int inner, int samples=SAMPLES, int warm=8) {
    for(int i=0;i<warm;i++) fn();
    std::vector<double> x;
    for(int s=0;s<samples;s++){
        auto a=Clock::now();
        for(int i=0;i<inner;i++) fn();
        auto b=Clock::now();
        x.push_back(std::chrono::duration<double,std::micro>(b-a).count()/inner);
    }
    return summarize(x, inner);
}
static void row(const std::string& name, const Stats& s, const std::string& note=""){
    std::cout << name << "," << std::fixed << std::setprecision(6)
              << s.mean << "," << s.median << "," << s.sd << ","
              << s.minv << "," << s.p95 << "," << s.samples << ","
              << s.inner << ",\"" << note << "\"\n";
}
static void digest(const EVP_MD* md, const unsigned char* in, size_t n,
                   unsigned char* out){
    unsigned int outn=0;
    if(EVP_Digest(in,n,out,&outn,md,nullptr)!=1) die("EVP_Digest failed");
}
static bool aes_cbc_enc(EVP_CIPHER_CTX* c, const EVP_CIPHER* cipher,
                        const unsigned char* key, const unsigned char* iv,
                        const unsigned char* in, int n, unsigned char* out){
    int l=0,total=0;
    if(EVP_CIPHER_CTX_reset(c)!=1) return false;
    if(EVP_EncryptInit_ex(c,cipher,nullptr,key,iv)!=1) return false;
    if(EVP_CIPHER_CTX_set_padding(c,0)!=1) return false;
    if(EVP_EncryptUpdate(c,out,&l,in,n)!=1) return false; total+=l;
    if(EVP_EncryptFinal_ex(c,out+total,&l)!=1) return false; total+=l;
    return total==n;
}
static bool aes_cbc_dec(EVP_CIPHER_CTX* c, const EVP_CIPHER* cipher,
                        const unsigned char* key, const unsigned char* iv,
                        const unsigned char* in, int n, unsigned char* out){
    int l=0,total=0;
    if(EVP_CIPHER_CTX_reset(c)!=1) return false;
    if(EVP_DecryptInit_ex(c,cipher,nullptr,key,iv)!=1) return false;
    if(EVP_CIPHER_CTX_set_padding(c,0)!=1) return false;
    if(EVP_DecryptUpdate(c,out,&l,in,n)!=1) return false; total+=l;
    if(EVP_DecryptFinal_ex(c,out+total,&l)!=1) return false; total+=l;
    return total==n;
}
struct ECData {
    EC_GROUP* g=nullptr;
    BN_CTX* ctx=nullptr;
    BIGNUM *k=nullptr,*r=nullptr;
    EC_POINT *P=nullptr,*R=nullptr;
    EC_KEY* key=nullptr;
    explicit ECData(int nid){
        g=EC_GROUP_new_by_curve_name(nid); ctx=BN_CTX_new();
        k=BN_new(); r=BN_new();
        if(!g||!ctx||!k||!r) die("EC allocation");
        const BIGNUM* q=EC_GROUP_get0_order(g);
        if(BN_rand_range(k,q)!=1 || BN_rand_range(r,q)!=1) die("EC random");
        P=EC_POINT_new(g); R=EC_POINT_new(g);
        if(!P||!R) die("EC point allocation");
        if(EC_POINT_mul(g,P,r,nullptr,nullptr,ctx)!=1) die("EC setup");
        key=EC_KEY_new_by_curve_name(nid);
        if(!key || EC_KEY_generate_key(key)!=1) die("ECDSA keygen");
    }
    ~ECData(){
        EC_KEY_free(key); EC_POINT_free(P); EC_POINT_free(R);
        BN_free(k); BN_free(r); BN_CTX_free(ctx); EC_GROUP_free(g);
    }
    const BIGNUM* order() const { return EC_GROUP_get0_order(g); }
};

// ============================================================
// Concrete MVNO-HO normalization for the three primitives that
// are not uniquely instantiated by the source protocol:
//   T_Com    : Pedersen commitment over NIST P-256
//   T_Sanit  : DL-based chameleon-hash collision generation
//   T_SanVer : collision validation + ECDSA-P256 verification
//
// Setup/key generation is performed outside the timed regions.
// The chameleon hash is CH_Y(m,r) = m*G + r*Y, Y = x*G.
// A collision for m -> m' is:
//   r' = r + (m - m') * x^{-1} mod q.
// ============================================================
struct MVNOP256Bench {
    EC_GROUP* g = nullptr;
    BN_CTX* ctx = nullptr;
    BIGNUM* q = nullptr;

    // Pedersen commitment C = mG + rH.
    BIGNUM *ped_m = nullptr, *ped_r = nullptr;
    EC_POINT *ped_H = nullptr, *ped_mG = nullptr, *ped_rH = nullptr, *ped_C = nullptr;

    // DL-based chameleon hash.
    BIGNUM *ch_x = nullptr, *ch_x_inv = nullptr;
    BIGNUM *ch_m0 = nullptr, *ch_r0 = nullptr, *ch_m1 = nullptr, *ch_r1 = nullptr;
    BIGNUM *bn_delta = nullptr, *bn_tmp = nullptr;
    EC_POINT *ch_Y = nullptr, *ch_H0 = nullptr, *ch_H1 = nullptr;
    EC_POINT *ch_mG = nullptr, *ch_rY = nullptr;

    // Standard signature used by the chameleon-hash SanSig normalization.
    EC_KEY* sig_key = nullptr;
    std::vector<unsigned char> sig;
    std::array<unsigned char, 32> verify_digest{};
    std::array<unsigned char, 65> point_octets{};

    static void rand_nonzero(BIGNUM* x, const BIGNUM* mod) {
        do {
            if (BN_rand_range(x, mod) != 1) die("MVNO P-256 random scalar");
        } while (BN_is_zero(x));
    }

    MVNOP256Bench() {
        g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        ctx = BN_CTX_new();
        if (!g || !ctx) die("MVNO P-256 group allocation");

        q = BN_dup(EC_GROUP_get0_order(g));
        ped_m = BN_new(); ped_r = BN_new();
        ch_x = BN_new(); ch_x_inv = BN_new();
        ch_m0 = BN_new(); ch_r0 = BN_new(); ch_m1 = BN_new(); ch_r1 = BN_new();
        bn_delta = BN_new(); bn_tmp = BN_new();

        ped_H = EC_POINT_new(g); ped_mG = EC_POINT_new(g);
        ped_rH = EC_POINT_new(g); ped_C = EC_POINT_new(g);
        ch_Y = EC_POINT_new(g); ch_H0 = EC_POINT_new(g); ch_H1 = EC_POINT_new(g);
        ch_mG = EC_POINT_new(g); ch_rY = EC_POINT_new(g);

        if (!q || !ped_m || !ped_r || !ch_x || !ch_x_inv ||
            !ch_m0 || !ch_r0 || !ch_m1 || !ch_r1 || !bn_delta || !bn_tmp ||
            !ped_H || !ped_mG || !ped_rH || !ped_C ||
            !ch_Y || !ch_H0 || !ch_H1 || !ch_mG || !ch_rY)
            die("MVNO P-256 allocation");

        // ----- Pedersen public parameter H (setup only, untimed) -----
        BIGNUM* h_scalar = BN_new();
        if (!h_scalar) die("Pedersen H scalar allocation");
        rand_nonzero(h_scalar, q);
        if (EC_POINT_mul(g, ped_H, h_scalar, nullptr, nullptr, ctx) != 1)
            die("Pedersen H setup");
        BN_clear_free(h_scalar);

        rand_nonzero(ped_m, q);
        rand_nonzero(ped_r, q);
        pedersen_commit();

        // ----- Chameleon-hash key and one valid collision (untimed setup) -----
        rand_nonzero(ch_x, q);
        rand_nonzero(ch_m0, q);
        rand_nonzero(ch_r0, q);
        rand_nonzero(ch_m1, q);

        if (EC_POINT_mul(g, ch_Y, ch_x, nullptr, nullptr, ctx) != 1)
            die("chameleon public key setup");

        ch_hash(ch_H0, ch_m0, ch_r0);
        sanitize_collision();
        ch_hash(ch_H1, ch_m1, ch_r1);
        if (EC_POINT_cmp(g, ch_H0, ch_H1, ctx) != 0)
            die("chameleon collision self-check");

        // ----- ECDSA signature on the original chameleon-hash point -----
        sig_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!sig_key || EC_KEY_generate_key(sig_key) != 1)
            die("MVNO ECDSA keygen");

        const size_t oct_len = EC_POINT_point2oct(
            g, ch_H0, POINT_CONVERSION_COMPRESSED,
            point_octets.data(), point_octets.size(), ctx);
        if (oct_len == 0) die("chameleon point serialization");

        digest(EVP_sha256(), point_octets.data(), oct_len, verify_digest.data());

        unsigned int sig_len = static_cast<unsigned int>(ECDSA_size(sig_key));
        sig.resize(sig_len);
        if (ECDSA_sign(0, verify_digest.data(), verify_digest.size(),
                       sig.data(), &sig_len, sig_key) != 1)
            die("MVNO SanSig setup sign");
        sig.resize(sig_len);

        if (!sansig_verify())
            die("MVNO SanSig verify self-check");
    }

    void pedersen_commit() {
        // C = mG + rH. Randomness r is sampled outside this benchmark,
        // matching the protocol where r is generated before Com().
        if (EC_POINT_mul(g, ped_mG, ped_m, nullptr, nullptr, ctx) != 1)
            die("Pedersen mG");
        if (EC_POINT_mul(g, ped_rH, nullptr, ped_H, ped_r, ctx) != 1)
            die("Pedersen rH");
        if (EC_POINT_add(g, ped_C, ped_mG, ped_rH, ctx) != 1)
            die("Pedersen add");
    }

    void ch_hash(EC_POINT* out, const BIGNUM* m, const BIGNUM* r) {
        // CH_Y(m,r) = mG + rY.
        if (EC_POINT_mul(g, ch_mG, m, nullptr, nullptr, ctx) != 1)
            die("chameleon mG");
        if (EC_POINT_mul(g, ch_rY, nullptr, ch_Y, r, ctx) != 1)
            die("chameleon rY");
        if (EC_POINT_add(g, out, ch_mG, ch_rY, ctx) != 1)
            die("chameleon add");
    }

    void sanitize_collision() {
        // Full collision generation from the sanitizer trapdoor x:
        // r' = r + (m - m') * x^{-1} mod q.
        //
        // We deliberately include the modular inversion in the timed
        // operation rather than caching x^{-1}. This is the conservative
        // choice for the per-sanitization cost.
        if (!BN_mod_inverse(ch_x_inv, ch_x, q, ctx))
            die("chameleon collision inverse");
        if (BN_mod_sub(bn_delta, ch_m0, ch_m1, q, ctx) != 1)
            die("chameleon collision delta");
        if (BN_mod_mul(bn_tmp, bn_delta, ch_x_inv, q, ctx) != 1)
            die("chameleon collision multiply");
        if (BN_mod_add(ch_r1, ch_r0, bn_tmp, q, ctx) != 1)
            die("chameleon collision add");
    }

    bool sansig_verify() {
        // Recompute the sanitized chameleon hash, validate the collision,
        // hash the point, and verify the standard ECDSA signature.
        ch_hash(ch_H1, ch_m1, ch_r1);
        if (EC_POINT_cmp(g, ch_H0, ch_H1, ctx) != 0)
            return false;

        const size_t oct_len = EC_POINT_point2oct(
            g, ch_H1, POINT_CONVERSION_COMPRESSED,
            point_octets.data(), point_octets.size(), ctx);
        if (oct_len == 0)
            return false;

        digest(EVP_sha256(), point_octets.data(), oct_len, verify_digest.data());

        return ECDSA_verify(0, verify_digest.data(), verify_digest.size(),
                            sig.data(), static_cast<int>(sig.size()),
                            sig_key) == 1;
    }

    ~MVNOP256Bench() {
        EC_KEY_free(sig_key);

        EC_POINT_free(ch_rY); EC_POINT_free(ch_mG);
        EC_POINT_free(ch_H1); EC_POINT_free(ch_H0); EC_POINT_free(ch_Y);
        EC_POINT_free(ped_C); EC_POINT_free(ped_rH);
        EC_POINT_free(ped_mG); EC_POINT_free(ped_H);

        BN_clear_free(bn_tmp); BN_clear_free(bn_delta);
        BN_clear_free(ch_r1); BN_clear_free(ch_m1);
        BN_clear_free(ch_r0); BN_clear_free(ch_m0);
        BN_clear_free(ch_x_inv); BN_clear_free(ch_x);
        BN_clear_free(ped_r); BN_clear_free(ped_m);
        BN_free(q);
        BN_CTX_free(ctx);
        EC_GROUP_free(g);
    }
};

struct ElGamal {
    EC_GROUP* g=nullptr; BN_CTX* ctx=nullptr;
    BIGNUM *x=nullptr,*k=nullptr,*m=nullptr;
    EC_POINT *Y=nullptr,*M=nullptr,*C1=nullptr,*C2=nullptr,*tmp=nullptr,*out=nullptr;
    ElGamal(){
        g=EC_GROUP_new_by_curve_name(NID_secp256k1); ctx=BN_CTX_new();
        x=BN_new(); k=BN_new(); m=BN_new();
        if(!g||!ctx||!x||!k||!m) die("ElGamal allocation");
        const BIGNUM* q=EC_GROUP_get0_order(g);
        if(BN_rand_range(x,q)!=1||BN_rand_range(k,q)!=1||BN_rand_range(m,q)!=1)
            die("ElGamal random");
        Y=EC_POINT_new(g); M=EC_POINT_new(g); C1=EC_POINT_new(g);
        C2=EC_POINT_new(g); tmp=EC_POINT_new(g); out=EC_POINT_new(g);
        if(!Y||!M||!C1||!C2||!tmp||!out) die("ElGamal point allocation");
        if(EC_POINT_mul(g,Y,x,nullptr,nullptr,ctx)!=1 ||
           EC_POINT_mul(g,M,m,nullptr,nullptr,ctx)!=1) die("ElGamal setup");
        enc(); dec();
        if(EC_POINT_cmp(g,M,out,ctx)!=0) die("ElGamal self-check");
    }
    void enc(){
        if(EC_POINT_mul(g,C1,k,nullptr,nullptr,ctx)!=1) die("ElGamal C1");
        if(EC_POINT_mul(g,tmp,nullptr,Y,k,ctx)!=1) die("ElGamal kY");
        if(EC_POINT_add(g,C2,M,tmp,ctx)!=1) die("ElGamal C2");
    }
    void dec(){
        if(EC_POINT_mul(g,tmp,nullptr,C1,x,ctx)!=1) die("ElGamal xC1");
        if(EC_POINT_invert(g,tmp,ctx)!=1) die("ElGamal invert");
        if(EC_POINT_add(g,out,C2,tmp,ctx)!=1) die("ElGamal recover");
    }
    ~ElGamal(){
        EC_POINT_free(Y);EC_POINT_free(M);EC_POINT_free(C1);EC_POINT_free(C2);
        EC_POINT_free(tmp);EC_POINT_free(out);
        BN_free(x);BN_free(k);BN_free(m);BN_CTX_free(ctx);EC_GROUP_free(g);
    }
};
struct Shamir35 {
    BN_CTX* ctx=nullptr;
    BIGNUM *q=nullptr,*secret=nullptr,*a1=nullptr,*a2=nullptr,*rec=nullptr;
    std::array<BIGNUM*,5> xs{},ys{};
    explicit Shamir35(const BIGNUM* mod){
        ctx=BN_CTX_new(); q=BN_dup(mod); secret=BN_new();
        a1=BN_new(); a2=BN_new(); rec=BN_new();
        if(!ctx||!q||!secret||!a1||!a2||!rec) die("Shamir allocation");
        for(int i=0;i<5;i++){ xs[i]=BN_new(); ys[i]=BN_new(); BN_set_word(xs[i],i+1); }
        if(BN_rand_range(secret,q)!=1) die("Shamir secret");
        split(); recover();
        if(BN_cmp(secret,rec)!=0) die("Shamir self-check");
    }
    void split(){
        if(BN_rand_range(a1,q)!=1 || BN_rand_range(a2,q)!=1) die("Shamir coeff");
        BN_CTX_start(ctx);
        BIGNUM* t1=BN_CTX_get(ctx); BIGNUM* t2=BN_CTX_get(ctx); BIGNUM* x2=BN_CTX_get(ctx);
        for(int i=0;i<5;i++){
            if(BN_mod_mul(t1,a1,xs[i],q,ctx)!=1) die("Shamir mul1");
            if(BN_mod_sqr(x2,xs[i],q,ctx)!=1) die("Shamir sqr");
            if(BN_mod_mul(t2,a2,x2,q,ctx)!=1) die("Shamir mul2");
            if(BN_mod_add(ys[i],secret,t1,q,ctx)!=1 ||
               BN_mod_add(ys[i],ys[i],t2,q,ctx)!=1) die("Shamir add");
        }
        BN_CTX_end(ctx);
    }
    void recover(){
        BN_zero(rec);
        BN_CTX_start(ctx);
        BIGNUM* num=BN_CTX_get(ctx); BIGNUM* den=BN_CTX_get(ctx);
        BIGNUM* tmp=BN_CTX_get(ctx); BIGNUM* inv=BN_CTX_get(ctx);
        BIGNUM* lam=BN_CTX_get(ctx); BIGNUM* term=BN_CTX_get(ctx);
        for(int i=0;i<3;i++){
            BN_one(num); BN_one(den);
            for(int j=0;j<3;j++) if(i!=j){
                if(BN_mod_sub(tmp,q,xs[j],q,ctx)!=1 ||
                   BN_mod_mul(num,num,tmp,q,ctx)!=1) die("Shamir num");
                if(BN_mod_sub(tmp,xs[i],xs[j],q,ctx)!=1 ||
                   BN_mod_mul(den,den,tmp,q,ctx)!=1) die("Shamir den");
            }
            if(!BN_mod_inverse(inv,den,q,ctx)) die("Shamir inverse");
            if(BN_mod_mul(lam,num,inv,q,ctx)!=1 ||
               BN_mod_mul(term,ys[i],lam,q,ctx)!=1 ||
               BN_mod_add(rec,rec,term,q,ctx)!=1) die("Shamir recover");
        }
        BN_CTX_end(ctx);
    }
    ~Shamir35(){
        for(auto p:xs) BN_free(p); for(auto p:ys) BN_free(p);
        BN_free(rec);BN_free(a2);BN_free(a1);BN_free(secret);BN_free(q);BN_CTX_free(ctx);
    }
};
int main(){
    try{
        std::array<unsigned char,HASH_BYTES> msg{};
        std::array<unsigned char,EVP_MAX_MD_SIZE> out{};
        std::array<unsigned char,32> d256{}, hkey256{};
        std::array<unsigned char,64> d512{};
        if(RAND_bytes(msg.data(),msg.size())!=1 || RAND_bytes(hkey256.data(),hkey256.size())!=1)
            die("RAND_bytes");
        digest(EVP_sha256(),msg.data(),msg.size(),d256.data());
        digest(EVP_sha512(),msg.data(),msg.size(),d512.data());
        ECData p256(NID_X9_62_prime256v1), k1(NID_secp256k1);
        auto make_sig=[&](EC_KEY* key){
            unsigned int cap=(unsigned int)ECDSA_size(key), n=cap;
            std::vector<unsigned char> sig(cap);
            if(ECDSA_sign(0,d256.data(),d256.size(),sig.data(),&n,key)!=1) die("ECDSA setup sign");
            sig.resize(n); return sig;
        };
        auto sig_p256=make_sig(p256.key);
        auto sig_k1=make_sig(k1.key);
        std::vector<unsigned char> sigtmp_p256(ECDSA_size(p256.key));
        std::vector<unsigned char> sigtmp_k1(ECDSA_size(k1.key));
        ElGamal elg;
        Shamir35 shamir(p256.order());
        MVNOP256Bench mvno_p256;

        // ============================================================
        // Security-normalized pairing suite for Cross-Domain MEC.
        //
        // BLS12-381 is used as an approximately 128-bit classical-
        // security pairing curve.  mcl's C API is used deliberately so
        // that the measured primitives map directly to the paper's
        // T_bp (pairing) and T_mp (G1 point multiplication), while
        // exposing the previously hidden H:{0,1}* -> G1 cost.
        //
        // Setup, DST configuration, point generation, and scalar
        // generation are all outside the timed regions.
        // ============================================================
        if (mclBn_init(mclBls12_CurveFp381, MCLBN_COMPILED_TIME_VAR) != 0)
            die("mcl BLS12-381 initialization failed");
        if (mclBn_setMapToMode(MCL_MAP_TO_MODE_HASH_TO_CURVE) != 0)
            die("mcl hash-to-curve mode setup failed");

        static constexpr char BLS_G1_DST[] =
            "CROSS_DOMAIN_MEC_BLS12381G1_XMD:SHA-256_SSWU_RO_";
        static constexpr char BLS_G2_DST[] =
            "CROSS_DOMAIN_MEC_BLS12381G2_XMD:SHA-256_SSWU_RO_";
        if (mclBnG1_setDst(BLS_G1_DST, sizeof(BLS_G1_DST) - 1) != 0)
            die("mcl G1 DST setup failed");
        if (mclBnG2_setDst(BLS_G2_DST, sizeof(BLS_G2_DST) - 1) != 0)
            die("mcl G2 DST setup failed");

        mclBnG1 bls_g1{}, bls_g1_mul_out{}, bls_h2c_out{};
        mclBnG2 bls_g2{};
        mclBnFr bls_sk{};
        mclBnGT bls_gt{};

        std::array<unsigned char, HASH_BYTES> bls_msg_g1 = msg;
        std::array<unsigned char, HASH_BYTES> bls_msg_g2 = msg;
        bls_msg_g2[0] ^= 0xA5; // domain-separate the untimed setup point.

        if (mclBnG1_hashAndMapTo(&bls_g1, bls_msg_g1.data(), bls_msg_g1.size()) != 0)
            die("mcl BLS12-381 G1 setup hash-to-curve failed");
        if (mclBnG2_hashAndMapTo(&bls_g2, bls_msg_g2.data(), bls_msg_g2.size()) != 0)
            die("mcl BLS12-381 G2 setup hash-to-curve failed");
        if (mclBnFr_setByCSPRNG(&bls_sk) != 0)
            die("mcl BLS12-381 scalar generation failed");
        if (!mclBnG1_isValid(&bls_g1) || !mclBnG1_isValidOrder(&bls_g1))
            die("mcl BLS12-381 invalid G1 setup point");
        if (!mclBnG2_isValid(&bls_g2) || !mclBnG2_isValidOrder(&bls_g2))
            die("mcl BLS12-381 invalid G2 setup point");

        // PBC Type-A pairing suite (historical baseline only).
        // Generate the parameter file once; all later runs reuse exactly the same file.
        ensure_type_a_param();
        std::ifstream pbc_file(PBC_PARAM_PATH, std::ios::binary);
        if (!pbc_file) die("cannot open PBC parameter file");
        std::string pbc_param_text((std::istreambuf_iterator<char>(pbc_file)),
                                   std::istreambuf_iterator<char>());
        if (pbc_param_text.empty()) die("empty PBC parameter file");
        pairing_t pairing;
        if (pairing_init_set_buf(pairing,
                                 pbc_param_text.data(),
                                 pbc_param_text.size()) != 0)
            die("pairing_init_set_buf failed");
        element_t pbc_P, pbc_Q, pbc_k, pbc_R, pbc_ePQ;
        element_init_G1(pbc_P, pairing);
        element_init_G1(pbc_Q, pairing);
        element_init_Zr(pbc_k, pairing);
        element_init_G1(pbc_R, pairing);
        element_init_GT(pbc_ePQ, pairing);
        element_random(pbc_P);
        element_random(pbc_Q);
        element_random(pbc_k);
        // RFC 3526 Group 15: 3072-bit MODP modulus.
        // Exponent length is normalized to 256 bits.
        BN_CTX* modexp_ctx = BN_CTX_new();
        BIGNUM* modexp_p = BN_get_rfc3526_prime_3072(nullptr);
        BIGNUM* modexp_g = BN_new();
        BIGNUM* modexp_seed = BN_new();
        BIGNUM* modexp_base = BN_new();
        BIGNUM* modexp_x = BN_new();
        BIGNUM* modexp_result = BN_new();
        BN_MONT_CTX* modexp_mont = BN_MONT_CTX_new();
        if (!modexp_ctx || !modexp_p || !modexp_g || !modexp_seed ||
            !modexp_base || !modexp_x || !modexp_result || !modexp_mont)
            die("MODP allocation");
        if (BN_set_word(modexp_g, 2) != 1)
            die("MODP generator setup");
        if (BN_rand(modexp_seed, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1)
            die("MODP base seed");
        if (BN_mod_exp(modexp_base, modexp_g, modexp_seed, modexp_p, modexp_ctx) != 1)
            die("MODP base setup");
        if (BN_rand(modexp_x, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1)
            die("MODP exponent setup");
        BN_set_flags(modexp_x, BN_FLG_CONSTTIME);
        if (BN_MONT_CTX_set(modexp_mont, modexp_p, modexp_ctx) != 1)
            die("MODP Montgomery setup");
        // RSA-4096 key generation is setup cost, not included in primitive timing.
        EVP_PKEY_CTX* kg=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr);
        EVP_PKEY* rsa=nullptr;
        if(!kg||EVP_PKEY_keygen_init(kg)<=0||
           EVP_PKEY_CTX_set_rsa_keygen_bits(kg,4096)<=0||
           EVP_PKEY_keygen(kg,&rsa)<=0) die("RSA keygen");
        EVP_PKEY_CTX_free(kg);
        EVP_PKEY_CTX *rs=EVP_PKEY_CTX_new(rsa,nullptr), *rv=EVP_PKEY_CTX_new(rsa,nullptr);
        if(!rs||!rv) die("RSA sign ctx");
        if(EVP_PKEY_sign_init(rs)<=0 ||
           EVP_PKEY_CTX_set_rsa_padding(rs,RSA_PKCS1_PSS_PADDING)<=0 ||
           EVP_PKEY_CTX_set_signature_md(rs,EVP_sha512())<=0 ||
           EVP_PKEY_CTX_set_rsa_pss_saltlen(rs,RSA_PSS_SALTLEN_DIGEST)<=0) die("RSA sign init");
        if(EVP_PKEY_verify_init(rv)<=0 ||
           EVP_PKEY_CTX_set_rsa_padding(rv,RSA_PKCS1_PSS_PADDING)<=0 ||
           EVP_PKEY_CTX_set_signature_md(rv,EVP_sha512())<=0 ||
           EVP_PKEY_CTX_set_rsa_pss_saltlen(rv,RSA_PSS_SALTLEN_DIGEST)<=0) die("RSA verify init");
        size_t rsz=EVP_PKEY_get_size(rsa), rsiglen=rsz;
        std::vector<unsigned char> rsig(rsz), rsigtmp(rsz);
        if(EVP_PKEY_sign(rs,rsig.data(),&rsiglen,d512.data(),d512.size())<=0) die("RSA setup sign");
        rsig.resize(rsiglen);
        EVP_PKEY_CTX *re=EVP_PKEY_CTX_new(rsa,nullptr), *rd=EVP_PKEY_CTX_new(rsa,nullptr);
        if(!re||!rd) die("RSA enc ctx");
        if(EVP_PKEY_encrypt_init(re)<=0 ||
           EVP_PKEY_CTX_set_rsa_padding(re,RSA_PKCS1_OAEP_PADDING)<=0 ||
           EVP_PKEY_CTX_set_rsa_oaep_md(re,EVP_sha256())<=0 ||
           EVP_PKEY_CTX_set_rsa_mgf1_md(re,EVP_sha256())<=0) die("RSA enc init");
        if(EVP_PKEY_decrypt_init(rd)<=0 ||
           EVP_PKEY_CTX_set_rsa_padding(rd,RSA_PKCS1_OAEP_PADDING)<=0 ||
           EVP_PKEY_CTX_set_rsa_oaep_md(rd,EVP_sha256())<=0 ||
           EVP_PKEY_CTX_set_rsa_mgf1_md(rd,EVP_sha256())<=0) die("RSA dec init");
        std::array<unsigned char,32> rplain{};
        RAND_bytes(rplain.data(),rplain.size());
        std::vector<unsigned char> rct(rsz), renc_tmp(rsz), rdec_tmp(rsz);
        size_t rctlen=rct.size();
        if(EVP_PKEY_encrypt(re,rct.data(),&rctlen,rplain.data(),rplain.size())<=0) die("RSA setup enc");
        rct.resize(rctlen);

        // ============================================================
        // RSA-2048 setup for MVNO-HO public-key operations
        // ============================================================
        // Key-generation context. Context construction itself is outside the timed region.
        EVP_PKEY_CTX* rsa2048_kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!rsa2048_kctx)
            die("RSA-2048 keygen ctx");
        if (EVP_PKEY_keygen_init(rsa2048_kctx) <= 0)
            die("RSA-2048 keygen init");
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(rsa2048_kctx, 2048) <= 0)
            die("RSA-2048 set key bits");

        // Generate one untimed RSA-2048 key pair.
        // This key is reused for the encryption/decryption benchmarks.
        EVP_PKEY* rsa2048_key = nullptr;
        if (EVP_PKEY_keygen(rsa2048_kctx, &rsa2048_key) <= 0)
            die("RSA-2048 setup keygen");

        // Fixed 128-byte plaintext.
        // RSA-2048 + OAEP-SHA256 supports at most 190 bytes.
        constexpr size_t RSA2048_MSG_LEN = 128;
        unsigned char rsa2048_msg[RSA2048_MSG_LEN];
        if (RAND_bytes(rsa2048_msg, static_cast<int>(sizeof(rsa2048_msg))) != 1)
            die("RSA-2048 RAND_bytes");

        // ---------------- Encryption context ----------------
        EVP_PKEY_CTX* rsa2048_enc_ctx = EVP_PKEY_CTX_new(rsa2048_key, nullptr);
        if (!rsa2048_enc_ctx)
            die("RSA-2048 encrypt ctx");
        if (EVP_PKEY_encrypt_init(rsa2048_enc_ctx) <= 0)
            die("RSA-2048 encrypt init");
        if (EVP_PKEY_CTX_set_rsa_padding(rsa2048_enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            die("RSA-2048 OAEP padding");
        if (EVP_PKEY_CTX_set_rsa_oaep_md(rsa2048_enc_ctx, EVP_sha256()) <= 0)
            die("RSA-2048 OAEP SHA256");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(rsa2048_enc_ctx, EVP_sha256()) <= 0)
            die("RSA-2048 MGF1 SHA256");

        // RSA-2048 ciphertext length = 256 bytes.
        std::vector<unsigned char> rsa2048_ciphertext(static_cast<size_t>(EVP_PKEY_get_size(rsa2048_key)));
        size_t rsa2048_ciphertext_len = rsa2048_ciphertext.size();

        // Produce one valid ciphertext outside the timed region for the decryption benchmark.
        if (EVP_PKEY_encrypt(
                rsa2048_enc_ctx,
                rsa2048_ciphertext.data(),
                &rsa2048_ciphertext_len,
                rsa2048_msg,
                sizeof(rsa2048_msg)) <= 0)
            die("RSA-2048 setup encryption");

        // ---------------- Decryption context ----------------
        EVP_PKEY_CTX* rsa2048_dec_ctx = EVP_PKEY_CTX_new(rsa2048_key, nullptr);
        if (!rsa2048_dec_ctx)
            die("RSA-2048 decrypt ctx");
        if (EVP_PKEY_decrypt_init(rsa2048_dec_ctx) <= 0)
            die("RSA-2048 decrypt init");
        if (EVP_PKEY_CTX_set_rsa_padding(rsa2048_dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            die("RSA-2048 decrypt OAEP padding");
        if (EVP_PKEY_CTX_set_rsa_oaep_md(rsa2048_dec_ctx, EVP_sha256()) <= 0)
            die("RSA-2048 decrypt OAEP SHA256");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(rsa2048_dec_ctx, EVP_sha256()) <= 0)
            die("RSA-2048 decrypt MGF1 SHA256");
        std::vector<unsigned char> rsa2048_plaintext(static_cast<size_t>(EVP_PKEY_get_size(rsa2048_key)));
        // ============================================================
        // End RSA-2048 pre-setup
        // ============================================================

        std::array<unsigned char,16> k128{},iv{};
        std::array<unsigned char,32> k256{};
        std::array<unsigned char,AES_BYTES> apt{},ct128{},ct256{},adec{};
        RAND_bytes(k128.data(),k128.size()); RAND_bytes(k256.data(),k256.size());
        RAND_bytes(iv.data(),iv.size()); RAND_bytes(apt.data(),apt.size());
        EVP_CIPHER_CTX *ac=EVP_CIPHER_CTX_new(), *dc=EVP_CIPHER_CTX_new();
        if(!ac||!dc) die("AES ctx");
        if(!aes_cbc_enc(ac,EVP_aes_128_cbc(),k128.data(),iv.data(),apt.data(),apt.size(),ct128.data()) ||
           !aes_cbc_enc(ac,EVP_aes_256_cbc(),k256.data(),iv.data(),apt.data(),apt.size(),ct256.data()))
            die("AES setup");
        // 3GPP-style KDF core: S = FC || P0 || L0, with P0="Enc".
        std::array<unsigned char,6> S{0x00,'E','n','c',0x00,0x03};
        std::array<unsigned char,32> kdfkey{};
        RAND_bytes(kdfkey.data(),kdfkey.size());
        // HKDF-SHA256 primitives for protocols that explicitly use Extract/Expand.
        std::array<unsigned char,32> hkdf_salt{}, hkdf_ikm{}, hkdf_prk{}, hkdf_okm{};
        std::array<unsigned char,17> hkdf_info_counter{}; // 16-byte info || 0x01
        RAND_bytes(hkdf_salt.data(),hkdf_salt.size());
        RAND_bytes(hkdf_ikm.data(),hkdf_ikm.size());
        RAND_bytes(hkdf_info_counter.data(),16);
        hkdf_info_counter[16]=0x01;
        {
            unsigned int n=0;
            if(!HMAC(EVP_sha256(),hkdf_salt.data(),hkdf_salt.size(),
                     hkdf_ikm.data(),hkdf_ikm.size(),hkdf_prk.data(),&n))
                die("HKDF setup extract");
        }
        // Scalar-map benchmark: 256-bit input reduced modulo P-256 group order.
        std::array<unsigned char,32> scalar_bytes{};
        RAND_bytes(scalar_bytes.data(),scalar_bytes.size());
        BIGNUM* map_in=BN_new();
        BIGNUM* map_out=BN_new();
        if(!map_in||!map_out) die("scalar map allocation");
        // Fixed expected MAC for verify benchmark.
        std::array<unsigned char,EVP_MAX_MD_SIZE> expected_mac{};
        unsigned int expected_mac_len=0;
        if(!HMAC(EVP_sha256(),hkey256.data(),hkey256.size(),
                 msg.data(),msg.size(),expected_mac.data(),&expected_mac_len))
            die("HMAC setup verify");
        std::cout<<"# OpenSSL="<<OPENSSL_VERSION_TEXT<<"\n";
        std::cout<<"# HASH_BYTES=64; AES_BYTES=128; RSA=4096; Shamir=(3,5)\n";
        std::cout<<"# PBC=TypeA; rbits=160; qbits=512; param="<<PBC_PARAM_PATH
                 <<"; usage=historical-baseline-only\n";
        std::cout<<"# MCL_version=0x"<<std::hex<<mclBn_getVersion()<<std::dec
                 <<"; BLS12-381; security=approximately-128-bit-classical"
                 <<"; G1_bytes="<<mclBn_getG1ByteSize()
                 <<"; G2_bytes="<<mclBn_getG2ByteSize()
                 <<"; Fr_bytes="<<mclBn_getFrByteSize()<<"\n";
        std::cout<<"# BLS12-381_H2C=IETF-hash-to-curve-mode; input_bytes="<<HASH_BYTES
                 <<"; G1_DST="<<BLS_G1_DST<<"\n";
        std::cout<<"# MODP=RFC3526-group15-3072; exponent_bits=256\n";
        std::cout<<"# MVNO=Pedersen-P256; CH=DL-P256; SanSigVerify=CH-collision+SHA256+ECDSA-P256\n";
        std::cout<<"primitive,mean_us,median_us,stddev_us,min_us,p95_us,samples,inner_iterations,notes\n";
        row("T_SHA256_64B",bench([&]{digest(EVP_sha256(),msg.data(),msg.size(),out.data());},4000),
            "SHA-256 over 64-byte input");
        row("T_SHA512_64B",bench([&]{digest(EVP_sha512(),msg.data(),msg.size(),out.data());},4000),
            "SHA-512 over 64-byte input");
        row("T_HMAC_SHA256_64B",bench([&]{
            unsigned int n=0;
            if(!HMAC(EVP_sha256(),hkey256.data(),hkey256.size(),msg.data(),msg.size(),out.data(),&n))
                die("HMAC");
        },1500),"HMAC-SHA-256 over 64-byte input");
        row("T_HMAC_SHA256_verify_64B",bench([&]{
            unsigned int n=0;
            if(!HMAC(EVP_sha256(),hkey256.data(),hkey256.size(),
                     msg.data(),msg.size(),out.data(),&n)) die("HMAC verify compute");
            if(CRYPTO_memcmp(out.data(),expected_mac.data(),32)!=0) die("HMAC verify compare");
        },1500),"HMAC-SHA-256 recomputation + constant-time comparison");
        row("T_3GPP_KDF_HMAC_SHA256",bench([&]{
            unsigned int n=0;
            if(!HMAC(EVP_sha256(),kdfkey.data(),kdfkey.size(),S.data(),S.size(),out.data(),&n))
                die("KDF");
        },1500),"3GPP-style KDF core = HMAC-SHA-256(Key, FC||P0||L0)");
        row("T_HKDF_extract_SHA256",bench([&]{
            unsigned int n=0;
            if(!HMAC(EVP_sha256(),hkdf_salt.data(),hkdf_salt.size(),
                     hkdf_ikm.data(),hkdf_ikm.size(),hkdf_prk.data(),&n))
                die("HKDF extract");
        },1500),"HKDF-Extract using HMAC-SHA-256");
        row("T_HKDF_expand_SHA256_32B",bench([&]{
            unsigned int n=0;
            if(!HMAC(EVP_sha256(),hkdf_prk.data(),hkdf_prk.size(),
                     hkdf_info_counter.data(),hkdf_info_counter.size(),
                     hkdf_okm.data(),&n)) die("HKDF expand");
        },1500),"HKDF-Expand 32-byte output; one HMAC block");
        row("T_HKDF_full_SHA256_32B",bench([&]{
            unsigned int n1=0,n2=0;
            if(!HMAC(EVP_sha256(),hkdf_salt.data(),hkdf_salt.size(),
                     hkdf_ikm.data(),hkdf_ikm.size(),hkdf_prk.data(),&n1))
                die("HKDF full extract");
            if(!HMAC(EVP_sha256(),hkdf_prk.data(),hkdf_prk.size(),
                     hkdf_info_counter.data(),hkdf_info_counter.size(),
                     hkdf_okm.data(),&n2)) die("HKDF full expand");
        },800),"HKDF-Extract + HKDF-Expand, 32-byte output");
        row("T_scalar_map_mod_P256_order",bench([&]{
            if(!BN_bin2bn(scalar_bytes.data(),scalar_bytes.size(),map_in))
                die("scalar map bin2bn");
            if(BN_mod(map_out,map_in,p256.order(),p256.ctx)!=1)
                die("scalar map mod");
        },2500),"256-bit input reduced modulo P-256 group order");
        auto ecrows=[&](ECData& e,const std::string& tag){
            row("T_EC_fixed_base_mul_"+tag,bench([&]{
                if(EC_POINT_mul(e.g,e.R,e.k,nullptr,nullptr,e.ctx)!=1) die("EC fixed");
            },250),"k*G");
            row("T_EC_variable_base_mul_"+tag,bench([&]{
                if(EC_POINT_mul(e.g,e.R,nullptr,e.P,e.k,e.ctx)!=1) die("EC variable");
            },150),"k*P");
        };
        ecrows(p256,"P256");
        ecrows(k1,"secp256k1");
        row("T_ECDSA_sign_P256_prehashed",bench([&]{
            unsigned int n=sigtmp_p256.size();
            if(ECDSA_sign(0,d256.data(),d256.size(),sigtmp_p256.data(),&n,p256.key)!=1) die("ECDSA P256 sign");
        },80),"ECDSA P-256 signing of precomputed SHA-256 digest");
        row("T_ECDSA_verify_P256_prehashed",bench([&]{
            if(ECDSA_verify(0,d256.data(),d256.size(),sig_p256.data(),sig_p256.size(),p256.key)!=1) die("ECDSA P256 verify");
        },80),"ECDSA P-256 verification of precomputed SHA-256 digest");

        // MVNO-HO concrete normalization for Com / SanSig.Sanit / SanSig.Verify.
        row("T_Pedersen_commit_P256",bench([&]{
            mvno_p256.pedersen_commit();
        },150),"Pedersen commitment C=mG+rH over P-256; m and r pre-generated");

        row("T_CH_collision_P256",bench([&]{
            mvno_p256.sanitize_collision();
        },2500),"DL chameleon-hash collision generation over P-256; includes modular inversion");

        row("T_SanSig_verify_CH_ECDSA_P256",bench([&]{
            if(!mvno_p256.sansig_verify())
                die("MVNO SanSig verify");
        },80),"SanSig verification normalization: recompute/validate P-256 chameleon-hash collision + SHA-256 + ECDSA-P256 verify");
        row("T_ECDSA_sign_secp256k1_prehashed",bench([&]{
            unsigned int n=sigtmp_k1.size();
            if(ECDSA_sign(0,d256.data(),d256.size(),sigtmp_k1.data(),&n,k1.key)!=1) die("ECDSA k1 sign");
        },80),"ECDSA secp256k1 signing of precomputed SHA-256 digest");
        row("T_ECDSA_verify_secp256k1_prehashed",bench([&]{
            if(ECDSA_verify(0,d256.data(),d256.size(),sig_k1.data(),sig_k1.size(),k1.key)!=1) die("ECDSA k1 verify");
        },80),"ECDSA secp256k1 verification of precomputed SHA-256 digest");
        row("T_ECElGamal_encrypt_secp256k1",bench([&]{elg.enc();},80),
            "EC-ElGamal: C1=kG, C2=M+kY; message point pre-encoded");
        row("T_ECElGamal_decrypt_secp256k1",bench([&]{elg.dec();},100),
            "EC-ElGamal: M=C2-xC1");
        row("T_RSA4096_PSS_sign_SHA512_prehashed",bench([&]{
            size_t n=rsigtmp.size();
            if(EVP_PKEY_sign(rs,rsigtmp.data(),&n,d512.data(),d512.size())<=0) die("RSA sign");
        },5,31,5),"RSA-4096 PSS sign; padding is explicit experiment choice");
        row("T_RSA4096_PSS_verify_SHA512_prehashed",bench([&]{
            if(EVP_PKEY_verify(rv,rsig.data(),rsig.size(),d512.data(),d512.size())!=1) die("RSA verify");
        },20,31,5),"RSA-4096 PSS verify; padding is explicit experiment choice");
        row("T_RSA4096_OAEP_SHA256_encrypt_32B",bench([&]{
            size_t n=renc_tmp.size();
            if(EVP_PKEY_encrypt(re,renc_tmp.data(),&n,rplain.data(),rplain.size())<=0) die("RSA encrypt");
        },20,31,5),"RSA-4096 OAEP-SHA256; source paper did not specify padding");
        row("T_RSA4096_OAEP_SHA256_decrypt_32B",bench([&]{
            size_t n=rdec_tmp.size();
            if(EVP_PKEY_decrypt(rd,rdec_tmp.data(),&n,rct.data(),rct.size())<=0) die("RSA decrypt");
        },5,31,5),"RSA-4096 OAEP-SHA256; source paper did not specify padding");

        // ============================================================
        // RSA-2048 benchmarks for MVNO-HO
        // ============================================================
        // RSA-2048 key generation
        row("T_RSA2048_keygen",
            bench([&] {
                EVP_PKEY* tmp_key = nullptr;
                if (EVP_PKEY_keygen(rsa2048_kctx, &tmp_key) <= 0)
                    die("RSA-2048 timed keygen");
                EVP_PKEY_free(tmp_key);
            }, 1),
            "RSA-2048 key-pair generation");

        // RSA-2048 OAEP-SHA256 encryption, 128-byte plaintext
        row("T_RSA2048_OAEP_SHA256_encrypt_128B",
            bench([&] {
                size_t out_len = rsa2048_ciphertext.size();
                if (EVP_PKEY_encrypt(
                        rsa2048_enc_ctx,
                        rsa2048_ciphertext.data(),
                        &out_len,
                        rsa2048_msg,
                        sizeof(rsa2048_msg)) <= 0)
                    die("RSA-2048 timed encryption");
                rsa2048_ciphertext_len = out_len;
            }, 100),
            "RSA-2048 OAEP-SHA256 encryption, 128-byte plaintext");

        // RSA-2048 OAEP-SHA256 decryption, 256-byte ciphertext
        row("T_RSA2048_OAEP_SHA256_decrypt_128B",
            bench([&] {
                size_t out_len = rsa2048_plaintext.size();
                if (EVP_PKEY_decrypt(
                        rsa2048_dec_ctx,
                        rsa2048_plaintext.data(),
                        &out_len,
                        rsa2048_ciphertext.data(),
                        rsa2048_ciphertext_len) <= 0)
                    die("RSA-2048 timed decryption");
            }, 20),
            "RSA-2048 OAEP-SHA256 decryption of 128-byte plaintext");
        // ============================================================
        // End RSA2048 benchmark rows
        // ============================================================

        row("T_AES128_CBC_encrypt_128B",bench([&]{
            if(!aes_cbc_enc(ac,EVP_aes_128_cbc(),k128.data(),iv.data(),apt.data(),apt.size(),ct128.data())) die("AES128 enc");
        },2000),"AES-128-CBC 128B; mode is normalization choice");
        row("T_AES128_CBC_decrypt_128B",bench([&]{
            if(!aes_cbc_dec(dc,EVP_aes_128_cbc(),k128.data(),iv.data(),ct128.data(),ct128.size(),adec.data())) die("AES128 dec");
        },2000),"AES-128-CBC 128B; mode is normalization choice");
        row("T_AES256_CBC_encrypt_128B",bench([&]{
            if(!aes_cbc_enc(ac,EVP_aes_256_cbc(),k256.data(),iv.data(),apt.data(),apt.size(),ct256.data())) die("AES256 enc");
        },2000),"AES-256-CBC 128B; mode is normalization choice");
        row("T_AES256_CBC_decrypt_128B",bench([&]{
            if(!aes_cbc_dec(dc,EVP_aes_256_cbc(),k256.data(),iv.data(),ct256.data(),ct256.size(),adec.data())) die("AES256 dec");
        },2000),"AES-256-CBC 128B; mode is normalization choice");
        // Security-normalized Cross-Domain MEC primitives.
        row("T_pair_BLS12_381",bench([&]{
            mclBn_pairing(&bls_gt, &bls_g1, &bls_g2);
        },50,31,8),
            "mcl full optimal-Ate pairing e(G1,G2) on BLS12-381; includes Miller loop + final exponentiation");

        row("T_mul_G1_BLS12_381_CT",bench([&]{
            mclBnG1_mulCT(&bls_g1_mul_out, &bls_g1, &bls_sk);
        },100,31,8),
            "mcl constant-time secret-scalar G1 multiplication on BLS12-381; BLS signing primitive");

        row("T_h2c_G1_BLS12_381",bench([&]{
            if (mclBnG1_hashAndMapTo(&bls_h2c_out,
                                     bls_msg_g1.data(),
                                     bls_msg_g1.size()) != 0)
                die("mcl timed BLS12-381 G1 hash-to-curve failed");
        },100,31,8),
            "mcl hash-to-G1 on BLS12-381 in IETF hash-to-curve mode; 64-byte input; SHA-256 XMD ciphersuite");

        // Historical low-security Type-A measurements are retained only
        // for traceability; do not use these rows in the normalized table.
        row("T_bp_TypeA_160_512",bench([&]{
            pairing_apply(pbc_ePQ, pbc_P, pbc_Q, pairing);
        },100),"PBC Type-A bilinear pairing e(P,Q); rbits=160, qbits=512; HISTORICAL ONLY");
        row("T_mp_G1_TypeA_160_512",bench([&]{
            element_mul_zn(pbc_R, pbc_P, pbc_k);
        },200),"PBC Type-A G1 scalar multiplication k*P; rbits=160, qbits=512; HISTORICAL ONLY");
        row("T_Exp_MODP3072_exp256",bench([&]{
            if (BN_mod_exp_mont_consttime(modexp_result, modexp_base, modexp_x,
                                          modexp_p, modexp_ctx, modexp_mont) != 1)
                die("MODP exponentiation");
        },100),"RFC3526 Group15 3072-bit modular exponentiation; 256-bit constant-time exponent");
        row("T_Shamir35_split_P256_order",bench([&]{shamir.split();},100),
            "Shamir (t=3,n=5), 256-bit prime field; includes random coefficients");
        row("T_Shamir35_recover_3shares_P256_order",bench([&]{shamir.recover();},100),
            "3-of-5 Lagrange interpolation at x=0");
        element_clear(pbc_ePQ);
        element_clear(pbc_R);
        element_clear(pbc_k);
        element_clear(pbc_Q);
        element_clear(pbc_P);
        pairing_clear(pairing);
        BN_MONT_CTX_free(modexp_mont);
        BN_free(modexp_result);
        BN_free(modexp_x);
        BN_free(modexp_base);
        BN_free(modexp_seed);
        BN_free(modexp_g);
        BN_free(modexp_p);
        BN_CTX_free(modexp_ctx);
        BN_free(map_in); BN_free(map_out);
        EVP_CIPHER_CTX_free(ac); EVP_CIPHER_CTX_free(dc);
        EVP_PKEY_CTX_free(rs); EVP_PKEY_CTX_free(rv);
        EVP_PKEY_CTX_free(re); EVP_PKEY_CTX_free(rd); EVP_PKEY_free(rsa);

        // RSA2048 resource cleanup
        EVP_PKEY_CTX_free(rsa2048_enc_ctx);
        EVP_PKEY_CTX_free(rsa2048_dec_ctx);
        EVP_PKEY_free(rsa2048_key);
        EVP_PKEY_CTX_free(rsa2048_kctx);

        return 0;
    }catch(const std::exception& e){
        std::cerr<<"ERROR: "<<e.what()<<"\n";
        return 1;
    }
}
