// SPDX-License-Identifier: MIT
#include "bi_crypto_primitives.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <limits>
#include <stdexcept>
#include <string>

namespace e2b {
namespace {
using Ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using Md = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using Group = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using Point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using Bn = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BnCtx = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

void Require(bool ok, const char* failure) {
  if (!ok) throw std::runtime_error(failure);
}
Group NewGroup() {
  Group group(EC_GROUP_new_by_curve_name(NID_secp256k1), &EC_GROUP_free);
  Require(bool(group), "cannot instantiate secp256k1");
  return group;
}
BnCtx NewBnCtx() {
  BnCtx ctx(BN_CTX_new(), &BN_CTX_free);
  Require(bool(ctx), "cannot allocate BN_CTX");
  return ctx;
}
Point DecodePoint(const EC_GROUP* group, const Bytes& encoding, BN_CTX* ctx) {
  Require(encoding.size() == 33 || encoding.size() == 65,
          "invalid EC public-point encoding length");
  Point p(EC_POINT_new(group), &EC_POINT_free);
  Require(bool(p) && EC_POINT_oct2point(group, p.get(), encoding.data(), encoding.size(), ctx) == 1,
          "cannot decode elliptic-curve point");
  Require(EC_POINT_is_on_curve(group, p.get(), ctx) == 1 &&
          EC_POINT_is_at_infinity(group, p.get()) == 0, "EC point off curve or infinity");
  return p;
}
Bytes EncodePoint(const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
  const auto n = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
  Require(n == 33, "unexpected compressed secp256k1 point size");
  Bytes out(n);
  Require(EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                             out.data(), out.size(), ctx) == out.size(),
          "EC point encoding failed");
  return out;
}
} // namespace

EcKey::EcKey(EVP_PKEY* pkey) : key_(pkey, &EVP_PKEY_free) {
  Require(bool(key_), "invalid EC identity key");
}

EcKey EcKey::Generate() {
  Ctx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free);
  Require(bool(ctx) && EVP_PKEY_keygen_init(ctx.get()) == 1, "EC keygen init failed");
  Require(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp256k1) == 1,
          "cannot select secp256k1");
  EVP_PKEY* raw = nullptr;
  Require(EVP_PKEY_keygen(ctx.get(), &raw) == 1, "EC keygen failed");
  return EcKey(raw);
}

EcKey EcKey::ImportPublic(const Bytes& encoding) {
  auto group = NewGroup();
  auto bctx = NewBnCtx();
  auto point = DecodePoint(group.get(), encoding, bctx.get());
  // Canonicalize incoming encoding before importing (remove ambiguity).
  auto canonical = EncodePoint(group.get(), point.get(), bctx.get());
  Ctx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), &EVP_PKEY_CTX_free);
  Require(bool(ctx) && EVP_PKEY_fromdata_init(ctx.get()) == 1, "EC import init failed");
  char groupName[] = "secp256k1";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, groupName, 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, canonical.data(), canonical.size()),
      OSSL_PARAM_construct_end()
  };
  EVP_PKEY* raw = nullptr;
  Require(EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) == 1,
          "EC public key import failed");
  return EcKey(raw);
}

Bytes EcKey::PublicPoint() const {
  std::size_t size = 0;
  Require(EVP_PKEY_get_octet_string_param(key_.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                         nullptr, 0, &size) == 1,
          "cannot read EC public key size");
  Bytes encoded(size);
  Require(EVP_PKEY_get_octet_string_param(key_.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                         encoded.data(), encoded.size(), &size) == 1,
          "cannot read EC public key");
  encoded.resize(size);
  auto group = NewGroup();
  auto ctx = NewBnCtx();
  const auto point = DecodePoint(group.get(), encoded, ctx.get());
  return EncodePoint(group.get(), point.get(), ctx.get());
}

bool EcKey::HasPrivateKey() const {
  BIGNUM* x = nullptr;
  const int rc = EVP_PKEY_get_bn_param(key_.get(), OSSL_PKEY_PARAM_PRIV_KEY, &x);
  if (x != nullptr) BN_clear_free(x);
  return rc == 1;
}

std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> EcKey::PrivateScalar() const {
  BIGNUM* raw = nullptr;
  Require(EVP_PKEY_get_bn_param(key_.get(), OSSL_PKEY_PARAM_PRIV_KEY, &raw) == 1,
          "private scalar unavailable");
  return {raw, &BN_clear_free};
}

Bytes EcKey::SignSha256(const Bytes& message) const {
  Require(HasPrivateKey(), "cannot sign with public-only identity");
  Md ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  Require(bool(ctx) && EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                                         key_.get()) == 1,
          "ECDSA signing init failed");
  Require(EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) == 1,
          "ECDSA signing update failed");
  std::size_t size = 0;
  Require(EVP_DigestSignFinal(ctx.get(), nullptr, &size) == 1, "ECDSA sig size failed");
  Bytes signature(size);
  Require(EVP_DigestSignFinal(ctx.get(), signature.data(), &size) == 1,
          "ECDSA signing failed");
  signature.resize(size);
  return signature;
}

bool EcKey::VerifySha256(const Bytes& message, const Bytes& signature) const {
  Md ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  Require(bool(ctx) && EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(),
                                           nullptr, key_.get()) == 1,
          "ECDSA verification init failed");
  Require(EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) == 1,
          "ECDSA verification update failed");
  const int rc = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
  if (rc == 0) return false;
  Require(rc == 1, "ECDSA verification internal error");
  return true;
}

BiEphemeral::BiEphemeral() : scalar(nullptr, &BN_clear_free) {}
BiEphemeral BiEphemeral::Generate() {
  auto group = NewGroup();
  auto ctx = NewBnCtx();
  Bn order(BN_new(), &BN_clear_free);
  Require(bool(order) && EC_GROUP_get_order(group.get(), order.get(), ctx.get()) == 1,
          "EC group order unavailable");
  BiEphemeral e;
  e.scalar.reset(BN_new());
  Require(bool(e.scalar), "cannot allocate ephemeral scalar");
  do {
    Require(BN_rand_range(e.scalar.get(), order.get()) == 1, "random scalar failed");
  } while (BN_is_zero(e.scalar.get()));
  Point publicPoint(EC_POINT_new(group.get()), &EC_POINT_free);
  Require(bool(publicPoint) && EC_POINT_mul(group.get(), publicPoint.get(),
                                           e.scalar.get(), nullptr, nullptr, ctx.get()) == 1,
          "cannot generate ephemeral point");
  e.point = EncodePoint(group.get(), publicPoint.get(), ctx.get());
  return e;
}

Digest32 Sha256(const Bytes& data) {
  Digest32 out{};
  Require(SHA256(data.data(), data.size(), out.data()) != nullptr, "SHA-256 failed");
  return out;
}

Digest32 EvolveDomainKey(const EcKey& own, const BiEphemeral& ephemeral,
                         const Bytes& peerPublicPoint, const Bytes& peerEphemeralPoint) {
  Require(own.HasPrivateKey() && bool(ephemeral.scalar),
          "Bi key evolution requires private identity and ephemeral scalars");
  auto group = NewGroup();
  auto ctx = NewBnCtx();
  auto peerIdentity = DecodePoint(group.get(), peerPublicPoint, ctx.get());
  auto peerEphemeral = DecodePoint(group.get(), peerEphemeralPoint, ctx.get());
  Point peerSum(EC_POINT_new(group.get()), &EC_POINT_free);
  Point shared(EC_POINT_new(group.get()), &EC_POINT_free);
  Bn groupOrder(BN_new(), &BN_clear_free);
  Bn ownSum(BN_new(), &BN_clear_free);
  auto ownPriv = own.PrivateScalar();
  Require(bool(peerSum) && bool(shared) && bool(groupOrder) && bool(ownSum),
          "Bi key evolution allocation failed");
  Require(EC_GROUP_get_order(group.get(), groupOrder.get(), ctx.get()) == 1 &&
          BN_mod_add(ownSum.get(), ephemeral.scalar.get(), ownPriv.get(),
                     groupOrder.get(), ctx.get()) == 1, "Bi scalar summation failed");
  Require(!BN_is_zero(ownSum.get()), "Bi scalar summation resulted in zero");
  Require(EC_POINT_add(group.get(), peerSum.get(), peerIdentity.get(),
                       peerEphemeral.get(), ctx.get()) == 1 &&
          EC_POINT_is_at_infinity(group.get(), peerSum.get()) == 0,
          "invalid Bi peer point sum");
  Require(EC_POINT_mul(group.get(), shared.get(), nullptr, peerSum.get(),
                       ownSum.get(), ctx.get()) == 1 &&
          EC_POINT_is_at_infinity(group.get(), shared.get()) == 0,
          "Bi key evolution point multiplication failed");
  return Sha256(EncodePoint(group.get(), shared.get(), ctx.get()));
}
} // namespace e2b
