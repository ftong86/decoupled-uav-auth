// UAV-Mobility-Auth formal core: durable state store (SQLite, real file writes).
#include "uavma/state_store.h"

#include <sqlite3.h>

#include <stdexcept>

#include "uavma/bytes.h"
#include "uavma/crypto.h"

namespace uavma {
namespace {

Bytes session_encode(const Session& s) {
  std::vector<Bytes> parts{text(s.sid),
                           Bytes{static_cast<uint8_t>(s.st)},
                           be32(static_cast<uint32_t>(s.epoch)),
                           s.tctx,
                           s.xt_sk,
                           s.xt,
                           s.xu_sk,
                           s.th1,
                           s.th2,
                           s.kcf,
                           s.kcm,
                           s.ks,
                           s.delta,
                           s.tau_t,
                           s.tau_c,
                           state_encode(s.base),
                           state_encode(s.next),
                           be32(static_cast<uint32_t>(s.expiry_ms & 0xffffffffu)),
                           Bytes{static_cast<uint8_t>(s.m2_sent ? 1 : 0)},
                           Bytes{static_cast<uint8_t>(s.m3_sent ? 1 : 0)},
                           s.cached_m1,
                           text(s.target_id)};
  return enc_vec(parts);
}

struct Reader {
  const Bytes& b;
  size_t off = 0;
  explicit Reader(const Bytes& buf) : b(buf) {}
  Bytes next() {
    if (off + 4 > b.size()) throw std::runtime_error("session decode: truncated");
    uint32_t n = (static_cast<uint32_t>(b[off]) << 24) | (static_cast<uint32_t>(b[off + 1]) << 16) |
                 (static_cast<uint32_t>(b[off + 2]) << 8) | static_cast<uint32_t>(b[off + 3]);
    off += 4;
    if (off + n > b.size()) throw std::runtime_error("session decode: short field");
    Bytes r(b.begin() + off, b.begin() + off + n);
    off += n;
    return r;
  }
  uint32_t u32() {
    Bytes x = next();
    if (x.size() != 4) throw std::runtime_error("session decode: bad u32");
    return (static_cast<uint32_t>(x[0]) << 24) | (static_cast<uint32_t>(x[1]) << 16) |
           (static_cast<uint32_t>(x[2]) << 8) | static_cast<uint32_t>(x[3]);
  }
};

Session session_decode(const Bytes& b) {
  Reader r(b);
  Session s;
  s.sid = untext(r.next());
  {
    Bytes stb = r.next();
    s.st = static_cast<SessState>(stb.empty() ? 0u : stb[0]);
  }
  s.epoch = r.u32();
  s.tctx = r.next();
  s.xt_sk = r.next();
  s.xt = r.next();
  s.xu_sk = r.next();
  s.th1 = r.next();
  s.th2 = r.next();
  s.kcf = r.next();
  s.kcm = r.next();
  s.ks = r.next();
  s.delta = r.next();
  s.tau_t = r.next();
  s.tau_c = r.next();
  {
    Bytes sb = r.next();
    size_t o = 0;
    s.base = state_decode(sb, o);
  }
  {
    Bytes sb = r.next();
    size_t o = 0;
    s.next = state_decode(sb, o);
  }
  s.expiry_ms = static_cast<int64_t>(r.u32());
  {
    Bytes f = r.next();
    s.m2_sent = !f.empty() && f[0] != 0;
  }
  {
    Bytes f = r.next();
    s.m3_sent = !f.empty() && f[0] != 0;
  }
  s.cached_m1 = r.next();
  s.target_id = untext(r.next());
  return s;
}

Bytes pending_bytes(const Pending& p) {
  return enc({state_encode(p.base), state_encode(p.next), p.delta, p.sid,
              be32(static_cast<uint32_t>(p.epoch))});
}

Pending pending_from_bytes(const Bytes& b) {
  Reader r(b);
  Pending p;
  Bytes sb = r.next();
  size_t o = 0;
  p.base = state_decode(sb, o);
  Bytes nb = r.next();
  o = 0;
  p.next = state_decode(nb, o);
  p.delta = r.next();
  p.sid = r.next();
  p.epoch = r.u32();
  return p;
}

}  // namespace

StateStore::StateStore(const std::string& path) : path_(path) {
  if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
    std::string err = db_ ? sqlite3_errmsg(db_) : "sqlite open failed";
    if (db_) sqlite3_close(db_);
    db_ = nullptr;
    throw std::runtime_error("state store open failed: " + err);
  }
  exec("PRAGMA journal_mode=WAL;");
  exec("CREATE TABLE IF NOT EXISTS committed(d TEXT PRIMARY KEY, v INTEGER, blob BLOB);");
  exec("CREATE TABLE IF NOT EXISTS pending(d TEXT PRIMARY KEY, present INTEGER, blob BLOB);");
  exec("CREATE TABLE IF NOT EXISTS uav_state(d TEXT PRIMARY KEY, v INTEGER, blob BLOB);");
  exec("CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, d TEXT, blob BLOB);");
  exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);");
}

StateStore::~StateStore() { close(); }

void StateStore::close() {
  if (db_) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

void StateStore::exec(const std::string& sql) {
  char* err = nullptr;
  if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
    std::string msg = err ? err : "sqlite exec failed";
    sqlite3_free(err);
    throw std::runtime_error("state store exec failed: " + msg);
  }
}

namespace {
struct Stmt {
  sqlite3* db = nullptr;
  sqlite3_stmt* st = nullptr;
  ~Stmt() {
    if (st) sqlite3_finalize(st);
  }
};
}  // namespace

void StateStore::bind_and_step(const std::string& sql, const std::vector<Bytes>& blobs,
                               const std::vector<long long>& ints) {
  Stmt s;
  s.db = db_;
  if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s.st, nullptr) != SQLITE_OK)
    throw std::runtime_error(std::string("prepare failed: ") + sqlite3_errmsg(db_));
  int idx = 1;
  for (long long v : ints) sqlite3_bind_int64(s.st, idx++, v);
  for (const Bytes& b : blobs)
    sqlite3_bind_blob(s.st, idx++, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT);
  if (sqlite3_step(s.st) != SQLITE_DONE)
    throw std::runtime_error(std::string("step failed: ") + sqlite3_errmsg(db_));
}

void StateStore::save_committed(Domain d, const State& s) {
  std::string ds = domain_str(d);
  Stmt st;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO committed(d,v,blob) VALUES(?,?,?) "
                         "ON CONFLICT(d) DO UPDATE SET v=excluded.v, blob=excluded.blob;",
                         -1, &st.st, nullptr) != SQLITE_OK)
    throw std::runtime_error("prepare committed failed");
  sqlite3_bind_text(st.st, 1, ds.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st.st, 2, static_cast<long long>(s.v));
  Bytes b = state_encode(s);
  sqlite3_bind_blob(st.st, 3, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT);
  if (sqlite3_step(st.st) != SQLITE_DONE)
    throw std::runtime_error(std::string("committed step failed: ") + sqlite3_errmsg(db_));
}

bool StateStore::load_committed(Domain d, State& out) {
  Stmt s;
  if (sqlite3_prepare_v2(db_, "SELECT blob FROM committed WHERE d=?;", -1, &s.st, nullptr) !=
      SQLITE_OK)
    return false;
  std::string ds = domain_str(d);
  sqlite3_bind_text(s.st, 1, ds.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(s.st) != SQLITE_ROW) return false;
  const void* blob = sqlite3_column_blob(s.st, 0);
  int n = sqlite3_column_bytes(s.st, 0);
  Bytes b(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + n);
  size_t o = 0;
  out = state_decode(b, o);
  return true;
}

void StateStore::save_pending(Domain d, const std::optional<Pending>& p) {
  std::string ds = domain_str(d);
  Stmt s;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO pending(d,present,blob) VALUES(?,?,?) "
                         "ON CONFLICT(d) DO UPDATE SET present=excluded.present, "
                         "blob=excluded.blob;",
                         -1, &s.st, nullptr) != SQLITE_OK)
    throw std::runtime_error("prepare pending failed");
  sqlite3_bind_text(s.st, 1, ds.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(s.st, 2, p ? 1 : 0);
  if (p) {
    Bytes b = pending_bytes(*p);
    sqlite3_bind_blob(s.st, 3, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT);
  } else {
    sqlite3_bind_null(s.st, 3);
  }
  if (sqlite3_step(s.st) != SQLITE_DONE)
    throw std::runtime_error(std::string("pending step failed: ") + sqlite3_errmsg(db_));
}

bool StateStore::load_pending(Domain d, std::optional<Pending>& out) {
  Stmt s;
  if (sqlite3_prepare_v2(db_, "SELECT present,blob FROM pending WHERE d=?;", -1, &s.st, nullptr) !=
      SQLITE_OK)
    return false;
  std::string ds = domain_str(d);
  sqlite3_bind_text(s.st, 1, ds.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(s.st) != SQLITE_ROW) return false;
  int present = sqlite3_column_int(s.st, 0);
  if (!present) {
    out.reset();
    return true;
  }
  const void* blob = sqlite3_column_blob(s.st, 1);
  int n = sqlite3_column_bytes(s.st, 1);
  Bytes b(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + n);
  out = pending_from_bytes(b);
  return true;
}

void StateStore::save_uav(Domain d, const State& s) {
  std::string ds = domain_str(d);
  Stmt st;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO uav_state(d,v,blob) VALUES(?,?,?) "
                         "ON CONFLICT(d) DO UPDATE SET v=excluded.v, blob=excluded.blob;",
                         -1, &st.st, nullptr) != SQLITE_OK)
    throw std::runtime_error("prepare uav_state failed");
  sqlite3_bind_text(st.st, 1, ds.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st.st, 2, static_cast<long long>(s.v));
  Bytes b = state_encode(s);
  sqlite3_bind_blob(st.st, 3, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT);
  if (sqlite3_step(st.st) != SQLITE_DONE)
    throw std::runtime_error(std::string("uav_state step failed: ") + sqlite3_errmsg(db_));
}

bool StateStore::load_uav(Domain d, State& out) {
  Stmt s;
  if (sqlite3_prepare_v2(db_, "SELECT blob FROM uav_state WHERE d=?;", -1, &s.st, nullptr) !=
      SQLITE_OK)
    return false;
  std::string ds = domain_str(d);
  sqlite3_bind_text(s.st, 1, ds.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(s.st) != SQLITE_ROW) return false;
  const void* blob = sqlite3_column_blob(s.st, 0);
  int n = sqlite3_column_bytes(s.st, 0);
  Bytes b(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + n);
  size_t o = 0;
  out = state_decode(b, o);
  return true;
}

void StateStore::save_session(Domain d, const Session& s) {
  std::string ds = domain_str(d);
  Stmt st;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO sessions(sid,d,blob) VALUES(?,?,?) "
                         "ON CONFLICT(sid) DO UPDATE SET d=excluded.d, blob=excluded.blob;",
                         -1, &st.st, nullptr) != SQLITE_OK)
    throw std::runtime_error("prepare session failed");
  sqlite3_bind_text(st.st, 1, s.sid.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st.st, 2, ds.c_str(), -1, SQLITE_TRANSIENT);
  Bytes b = session_encode(s);
  sqlite3_bind_blob(st.st, 3, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT);
  if (sqlite3_step(st.st) != SQLITE_DONE)
    throw std::runtime_error(std::string("session step failed: ") + sqlite3_errmsg(db_));
}

bool StateStore::load_session(Domain d, const std::string& sid, Session& out) {
  (void)d;
  Stmt s;
  if (sqlite3_prepare_v2(db_, "SELECT blob FROM sessions WHERE sid=?;", -1, &s.st, nullptr) !=
      SQLITE_OK)
    return false;
  sqlite3_bind_text(s.st, 1, sid.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(s.st) != SQLITE_ROW) return false;
  const void* blob = sqlite3_column_blob(s.st, 0);
  int n = sqlite3_column_bytes(s.st, 0);
  Bytes b(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + n);
  out = session_decode(b);
  return true;
}

void StateStore::save_meta(const std::string& k, const std::string& v) {
  Stmt st;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET "
                         "v=excluded.v;",
                         -1, &st.st, nullptr) != SQLITE_OK)
    throw std::runtime_error("prepare meta failed");
  sqlite3_bind_text(st.st, 1, k.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st.st, 2, v.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st.st) != SQLITE_DONE)
    throw std::runtime_error(std::string("meta step failed: ") + sqlite3_errmsg(db_));
}

bool StateStore::load_meta(const std::string& k, std::string& v) {
  Stmt s;
  if (sqlite3_prepare_v2(db_, "SELECT v FROM meta WHERE k=?;", -1, &s.st, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_text(s.st, 1, k.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(s.st) != SQLITE_ROW) return false;
  const unsigned char* t = sqlite3_column_text(s.st, 0);
  v = t ? reinterpret_cast<const char*>(t) : "";
  return true;
}

}  // namespace uavma
