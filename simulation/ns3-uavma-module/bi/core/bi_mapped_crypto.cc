// SPDX-License-Identifier: MIT
#include "bi_mapped_crypto.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <array>
#include <memory>
#include <stdexcept>

namespace e2b {
namespace {
void Check(bool ok,const char* what) { if(!ok) throw std::runtime_error(what); }
using Group=std::unique_ptr<EC_GROUP,decltype(&EC_GROUP_free)>;
using Point=std::unique_ptr<EC_POINT,decltype(&EC_POINT_free)>;
using Ctx=std::unique_ptr<BN_CTX,decltype(&BN_CTX_free)>;
using Cipher=std::unique_ptr<EVP_CIPHER_CTX,decltype(&EVP_CIPHER_CTX_free)>;
Group G(){ Group g(EC_GROUP_new_by_curve_name(NID_secp256k1), &EC_GROUP_free); Check(bool(g),"ECC group"); return g; }
Ctx C(){ Ctx c(BN_CTX_new(),&BN_CTX_free);Check(bool(c),"BN_CTX");return c; }
Bytes PublicFromPoint(const EC_GROUP* g,const EC_POINT* point,BN_CTX* ctx) {
  auto n=EC_POINT_point2oct(g,point,POINT_CONVERSION_COMPRESSED,nullptr,0,ctx);
  Check(n==33,"compressed point length"); Bytes out(n);
  Check(EC_POINT_point2oct(g,point,POINT_CONVERSION_COMPRESSED,out.data(),out.size(),ctx)==n,"point encode");
  return out;
}
Bytes SharedByScalar(const BIGNUM* scalar,const Bytes& peer) {
  auto g=G();auto c=C();
  Check(peer.size()==33,"peer point format");
  Point p(EC_POINT_new(g.get()),&EC_POINT_free),s(EC_POINT_new(g.get()),&EC_POINT_free);
  Check(bool(p)&&bool(s)&&EC_POINT_oct2point(g.get(),p.get(),peer.data(),peer.size(),c.get())==1,"peer point decode");
  Check(EC_POINT_is_on_curve(g.get(),p.get(),c.get())==1,"peer invalid point");
  Check(EC_POINT_mul(g.get(),s.get(),nullptr,p.get(),scalar,c.get())==1 &&
        EC_POINT_is_at_infinity(g.get(),s.get())==0,"ECDH multiply");
  return PublicFromPoint(g.get(),s.get(),c.get());
}
Bytes KeyForEcies(const Bytes& compressedShared) {
  Bytes input={'B','I','-','E','C','I','E','S','-','V','1'};
  input.insert(input.end(),compressedShared.begin(),compressedShared.end());
  const auto hashed=Sha256(input);return Bytes(hashed.begin(),hashed.end());
}
}
Bytes SealAesGcm(const Bytes& key32,const Bytes& plain,const Bytes& aad) {
  if(key32.size()!=32||plain.size()>65536)throw std::invalid_argument("invalid AEAD parameters");
  std::array<uint8_t,12> iv{};
  Check(RAND_bytes(iv.data(),static_cast<int>(iv.size()))==1,"RAND IV failed");
  Cipher ctx(EVP_CIPHER_CTX_new(),&EVP_CIPHER_CTX_free);
  Check(bool(ctx) && EVP_EncryptInit_ex(ctx.get(),EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1,"GCM init");
  Check(EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_GCM_SET_IVLEN,static_cast<int>(iv.size()),nullptr)==1 &&
        EVP_EncryptInit_ex(ctx.get(),nullptr,nullptr,key32.data(),iv.data())==1,"GCM key init");
  int len=0;
  if(!aad.empty()) Check(EVP_EncryptUpdate(ctx.get(),nullptr,&len,aad.data(),static_cast<int>(aad.size()))==1,"GCM AAD");
  Bytes cipher(plain.size()+16);
  Check(EVP_EncryptUpdate(ctx.get(),cipher.data(),&len,plain.data(),static_cast<int>(plain.size()))==1,"GCM encrypt");
  int total=len;
  Check(EVP_EncryptFinal_ex(ctx.get(),cipher.data()+total,&len)==1,"GCM final");
  total+=len; cipher.resize(static_cast<size_t>(total));
  std::array<uint8_t,16> tag{};
  Check(EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_GCM_GET_TAG,16,tag.data())==1,"GCM tag");
  Bytes out={'A','G','1'};
  out.insert(out.end(),iv.begin(),iv.end());
  out.insert(out.end(),cipher.begin(),cipher.end());
  out.insert(out.end(),tag.begin(),tag.end());
  return out;
}
Bytes OpenAesGcm(const Bytes& key32,const Bytes& sealed,const Bytes& aad) {
  if(key32.size()!=32||sealed.size()<31 || sealed.size()>65567 ||
     sealed[0]!='A'||sealed[1]!='G'||sealed[2]!='1')
     throw std::invalid_argument("invalid GCM envelope");
  const size_t n=sealed.size()-31;
  const auto* iv=sealed.data()+3;
  const auto* cipher=sealed.data()+15;
  const auto* tag=sealed.data()+15+n;
  Cipher ctx(EVP_CIPHER_CTX_new(),&EVP_CIPHER_CTX_free);
  Check(bool(ctx)&&EVP_DecryptInit_ex(ctx.get(),EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1,"GCM decrypt init");
  Check(EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_GCM_SET_IVLEN,12,nullptr)==1 &&
        EVP_DecryptInit_ex(ctx.get(),nullptr,nullptr,key32.data(),iv)==1,"GCM decrypt key");
  int len=0;
  if(!aad.empty()) Check(EVP_DecryptUpdate(ctx.get(),nullptr,&len,aad.data(),static_cast<int>(aad.size()))==1,"GCM decrypt AAD");
  Bytes plain(n+16);
  Check(EVP_DecryptUpdate(ctx.get(),plain.data(),&len,cipher,static_cast<int>(n))==1,"GCM decrypt data");
  int total=len;
  Check(EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_GCM_SET_TAG,16,const_cast<uint8_t*>(tag))==1,"GCM check tag");
  Check(EVP_DecryptFinal_ex(ctx.get(),plain.data()+total,&len)==1,"GCM authentication failed");
  total+=len;plain.resize(static_cast<size_t>(total));return plain;
}
Bytes SealEcies(const Bytes& recipientPublic,const Bytes& plain,const Bytes& aad) {
  BiEphemeral eph=BiEphemeral::Generate();
  const Bytes shared=SharedByScalar(eph.scalar.get(),recipientPublic);
  Bytes payload=SealAesGcm(KeyForEcies(shared),plain,aad);
  Bytes out={'E','C','1'};
  out.insert(out.end(),eph.point.begin(),eph.point.end());
  out.insert(out.end(),payload.begin(),payload.end());return out;
}
Bytes OpenEcies(const EcKey& recipient,const Bytes& sealed,const Bytes& aad) {
  if(!recipient.HasPrivateKey()||sealed.size()<67 ||
     sealed[0]!='E'||sealed[1]!='C'||sealed[2]!='1') throw std::invalid_argument("invalid ECIES envelope");
  const Bytes ephemeral(sealed.begin()+3,sealed.begin()+36);
  const auto scalar=recipient.PrivateScalar();
  const Bytes shared=SharedByScalar(scalar.get(),ephemeral);
  const Bytes payload(sealed.begin()+36,sealed.end());
  return OpenAesGcm(KeyForEcies(shared),payload,aad);
}
Bytes EstablishedKey(const std::string& seed,const std::string& domain) {
  const std::string label="BI_E2B_BOOTSTRAPPED_PREVIOUS_SESSION|"+seed+"|"+domain;
  const auto d=Sha256(Bytes(label.begin(),label.end()));return Bytes(d.begin(),d.end());
}
const EcKey& Identities::Private(Identity id) {
  auto it=identities_.find(id);
  if(it==identities_.end()) it=identities_.emplace(id,EcKey::Generate()).first;
  return it->second;
}
Bytes Identities::Public(Identity id) { return Private(id).PublicPoint(); }
} // namespace e2b
