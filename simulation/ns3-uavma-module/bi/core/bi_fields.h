// SPDX-License-Identifier: MIT
// Canonical, strictly bounded field encoding for the LTE Bi[11] mapping.
#pragma once
#include "bi_crypto_primitives.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>

namespace e2b {
using FieldId = std::uint8_t;
class Fields {
 public:
  void Put(FieldId key, const Bytes& v) {
    if (!key || v.size() > 16384 || !fields_.emplace(key, v).second)
      throw std::invalid_argument("duplicate/invalid Bi field");
  }
  void Put(FieldId key, const std::string& v) { Put(key, Bytes(v.begin(), v.end())); }
  void PutU64(FieldId key, std::uint64_t n) {
    Bytes b(8); for (int i=7; i>=0; --i) { b[static_cast<size_t>(i)]=static_cast<uint8_t>(n); n >>= 8; }
    Put(key, b);
  }
  bool Has(FieldId key) const { return fields_.count(key) != 0; }
  const Bytes& Get(FieldId key) const {
    auto it = fields_.find(key);
    if (it == fields_.end()) throw std::invalid_argument("Bi field missing: " + std::to_string(key));
    return it->second;
  }
  std::uint64_t GetU64(FieldId key) const {
    const auto& b = Get(key);
    if (b.size()!=8) throw std::invalid_argument("Bi noncanonical u64 field");
    std::uint64_t n=0; for(auto x:b) n=(n<<8)|x;
    return n;
  }
  Bytes Encode() const {
    Bytes b;
    if (fields_.size()>48) throw std::invalid_argument("excessive Bi fields");
    b.push_back(static_cast<uint8_t>(fields_.size()));
    for(const auto& pair: fields_) {
      b.push_back(pair.first);
      auto n=pair.second.size();
      b.push_back(static_cast<uint8_t>(n>>8)); b.push_back(static_cast<uint8_t>(n));
      b.insert(b.end(),pair.second.begin(),pair.second.end());
    }
    if(b.size()>16384) throw std::invalid_argument("Bi field stream too large");
    return b;
  }
  static Fields Decode(const Bytes& b) {
    if(b.empty() || b[0]>48) throw std::invalid_argument("invalid Bi fields header");
    Fields result; size_t pos=1;
    for(size_t i=0;i<b[0];++i) {
      if (pos+3>b.size()) throw std::invalid_argument("truncated Bi field header");
      const auto key=b[pos++]; size_t n=(static_cast<size_t>(b[pos])<<8)|b[pos+1]; pos+=2;
      if(pos+n>b.size()) throw std::invalid_argument("truncated Bi field value");
      result.Put(key,Bytes(b.begin()+static_cast<ptrdiff_t>(pos), b.begin()+static_cast<ptrdiff_t>(pos+n)));
      pos+=n;
    }
    if(pos!=b.size()) throw std::invalid_argument("Bi trailing field bytes");
    return result;
  }
  Bytes CanonicalExcluding(FieldId key) const {
    Fields c; for (const auto& v:fields_) if(v.first!=key) c.Put(v.first,v.second);
    return c.Encode();
  }
 private:
  std::map<FieldId,Bytes> fields_;
};
inline Bytes Concat(const Bytes& a,const Bytes& b) {
  Bytes o=a; o.insert(o.end(),b.begin(),b.end()); return o;
}
inline Bytes AsBytes(const Digest32& d) { return Bytes(d.begin(),d.end()); }
inline bool EqualSecret(const Bytes& a,const Bytes& b) {
  if(a.size()!=b.size()) return false;
  std::uint8_t diff=0; for(size_t i=0;i<a.size();++i) diff |= a[i]^b[i];
  return diff==0;
}
inline Bytes DomainDigest(const std::string& label,std::uint64_t round,const Bytes& v) {
  Fields f; f.Put(1,label);f.PutU64(2,round);f.Put(3,v);return AsBytes(Sha256(f.Encode()));
}
inline Bytes SignedText(const std::string& label,std::uint64_t round,const Fields& f,std::uint8_t signatureField) {
  return DomainDigest(label,round,f.CanonicalExcluding(signatureField));
}
inline Bytes TaggedHash(const std::string& label,std::uint64_t round,const Bytes& v,const Bytes& key={}) {
  return DomainDigest(label,round,Concat(v,key));
}
} // namespace e2b
