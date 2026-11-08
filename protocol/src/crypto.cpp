// UAV-Mobility-Auth formal core: cryptographic primitives (OpenSSL, P-256).
#include "uavma/crypto.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <memory>
#include <stdexcept>

namespace uavma {
namespace {

void require(bool ok, const std::string& msg) {
  if (!ok) throw std::runtime_error("crypto: " + msg);
}

using KeyPtr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

EC_GROUP* group() {
  static EC_GROUP* g = []() {
    EC_GROUP* x = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    require(x != nullptr, "curve allocation");
    return x;
  }();
  return g;
}

KeyPtr make_key() {
  KeyPtr k(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
  require(bool(k), "EC_KEY allocation");
  return k;
}

KeyPtr key_from_scalar(const Bytes& sk) {
  KeyPtr k = make_key();
  CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
  BnPtr bn(BN_bin2bn(sk.data(), static_cast<int>(sk.size()), nullptr), BN_free);
  PointPtr p(EC_POINT_new(group()), EC_POINT_free);
  require(bool(ctx) && bool(bn) && bool(p), "key context allocation");
  require(EC_POINT_mul(group(), p.get(), bn.get(), nullptr, nullptr, ctx.get()) == 1, "point mul");
  require(EC_KEY_set_private_key(k.get(), bn.get()) == 1, "set private");
  require(EC_KEY_set_public_key(k.get(), p.get()) == 1, "set public");
  return k;
}

KeyPtr key_from_public(const Bytes& pk) {
  KeyPtr k = make_key();
  CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
  PointPtr p(EC_POINT_new(group()), EC_POINT_free);
  require(bool(ctx) && bool(p), "public context allocation");
  require(EC_POINT_oct2point(group(), p.get(), pk.data(), pk.size(), ctx.get()) == 1,
          "malformed EC point");
  require(EC_KEY_set_public_key(k.get(), p.get()) == 1, "set public key");
  return k;
}

}  // namespace

OpCounters& counters() {
  static OpCounters c;
  return c;
}
void reset_counters() { counters().reset(); }

Bytes sha256(const Bytes& b) {
  Bytes out(SHA256_DIGEST_LENGTH);
  SHA256(b.data(), b.size(), out.data());
  ++counters().hash;
  return out;
}

Bytes hash_tag(const std::string& tag, const std::vector<Bytes>& xs) {
  std::vector<Bytes> parts;
  parts.push_back(text(tag));
  for (const Bytes& x : xs) parts.push_back(x);
  return sha256(enc_vec(parts));
}

Bytes hmac_sha256(const Bytes& key, const Bytes& b) {
  Bytes out(EVP_MAX_MD_SIZE);
  unsigned n = 0;
  require(HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), b.data(), b.size(),
               out.data(), &n) != nullptr,
          "HMAC failed");
  out.resize(n);
  ++counters().mac;
  return out;
}

Bytes kdf(const Bytes& key, const std::string& tag, const std::vector<Bytes>& xs) {
  std::vector<Bytes> parts;
  parts.push_back(text(tag));
  for (const Bytes& x : xs) parts.push_back(x);
  return hmac_sha256(key, enc_vec(parts));
}

Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm) { return hmac_sha256(salt, ikm); }

Bytes hkdf_expand(const Bytes& prk, const Bytes& info) {
  Bytes x = info;
  x.push_back(1);  // one-block expansion, counter = 1
  return hmac_sha256(prk, x);
}

Bytes random_bytes(size_t n) {
  Bytes b(n);
  require(RAND_bytes(b.data(), static_cast<int>(n)) == 1, "RAND_bytes failed");
  return b;
}

Bytes scalar_from_hash(const Bytes& h) {
  CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
  BnPtr bn(BN_bin2bn(h.data(), static_cast<int>(h.size()), nullptr), BN_free);
  BnPtr order(BN_new(), BN_free);
  require(bool(ctx) && bool(bn) && bool(order), "scalar allocation");
  require(EC_GROUP_get_order(group(), order.get(), ctx.get()) == 1, "group order");
  require(BN_mod(bn.get(), bn.get(), order.get(), ctx.get()) == 1, "scalar mod");
  if (BN_is_zero(bn.get())) require(BN_one(bn.get()) == 1, "scalar nonzero");
  Bytes out(32);
  require(BN_bn2binpad(bn.get(), out.data(), 32) == 32, "scalar pad");
  ++counters().h2s;
  return out;
}

Bytes pubkey_from_scalar(const Bytes& sk) {
  KeyPtr k = key_from_scalar(sk);
  CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
  const EC_POINT* p = EC_KEY_get0_public_key(k.get());
  size_t len = EC_POINT_point2oct(group(), p, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx.get());
  require(len == 33, "compressed point length");
  Bytes out(len);
  require(EC_POINT_point2oct(group(), p, POINT_CONVERSION_COMPRESSED, out.data(), out.size(),
                             ctx.get()) == len,
          "point2oct");
  ++counters().pts_mul;
  return out;
}

Bytes ecdh_shared(const Bytes& sk, const Bytes& peer_pk) {
  KeyPtr a = key_from_scalar(sk);
  KeyPtr b = key_from_public(peer_pk);
  Bytes z(32);
  int n = ECDH_compute_key(z.data(), static_cast<int>(z.size()),
                           EC_KEY_get0_public_key(b.get()), a.get(), nullptr);
  require(n == 32, "ECDH failed");
  ++counters().ecdh;
  return z;
}

Bytes ecdsa_sign(const Bytes& sk, const Bytes& digest) {
  KeyPtr k = key_from_scalar(sk);
  std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
      ECDSA_do_sign(digest.data(), static_cast<int>(digest.size()), k.get()), ECDSA_SIG_free);
  require(bool(sig), "ECDSA sign failed");
  const BIGNUM *r = nullptr, *s = nullptr;
  ECDSA_SIG_get0(sig.get(), &r, &s);
  Bytes out(64);
  require(BN_bn2binpad(r, out.data(), 32) == 32, "sig r pad");
  require(BN_bn2binpad(s, out.data() + 32, 32) == 32, "sig s pad");
  ++counters().sign;
  return out;
}

bool ecdsa_verify(const Bytes& pk, const Bytes& digest, const Bytes& sig) {
  ++counters().verify;
  if (sig.size() != 64) return false;
  KeyPtr k = key_from_public(pk);
  std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> es(ECDSA_SIG_new(), ECDSA_SIG_free);
  if (!es) return false;
  BnPtr r(BN_bin2bn(sig.data(), 32, nullptr), BN_free);
  BnPtr s(BN_bin2bn(sig.data() + 32, 32, nullptr), BN_free);
  if (!r || !s) return false;
  if (ECDSA_SIG_set0(es.get(), r.release(), s.release()) != 1) return false;
  return ECDSA_do_verify(digest.data(), static_cast<int>(digest.size()), es.get(), k.get()) == 1;
}

Bytes compress_point(const void* ec_point) {
  CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
  const EC_POINT* p = static_cast<const EC_POINT*>(ec_point);
  size_t len = EC_POINT_point2oct(group(), p, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx.get());
  Bytes out(len);
  EC_POINT_point2oct(group(), p, POINT_CONVERSION_COMPRESSED, out.data(), out.size(), ctx.get());
  return out;
}

}  // namespace uavma
