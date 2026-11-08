# S2 — 论文公式到代码的映射（Protocol → Code Mapping）

**来源**：`docs/paper.pdf` Section V；`docs/S0_protocol_message_table.md`；`docs/S0_state_machine_table.md`。
**状态**：S2 已实现并测试通过（`scripts/run_s2.sh`，`results/formal/S2-*`）。
**运行基线 run_id**：`20261008T075207Z-formal`

本文只说明"论文的每个密码操作落在哪个函数"，不声称任何性能指标。

---

## 1. 通用定义（公式 (1)–(2)）

| 论文记号 | 代码 | 文件 |
|---|---|---|
| `Enc(x1..xn)` 单射规范编码（4 字节长度前缀） | `enc()` / `enc_vec()` / `append_enc()` | `include/uavma/bytes.h` |
| `Hash(tag; x1..xn) = H(Enc(tag,x1..xn))` | `hash_tag(tag, xs)` | `src/crypto.cpp` |
| `KDF(k; tag, x1..xn) = HMAC(k, Enc(tag,x1..xn))` | `kdf(key, tag, xs)` | `src/crypto.cpp` |
| `H2S(·)` 哈希到标量 | `scalar_from_hash()` | `src/crypto.cpp` |
| `PUFEval_U(chi_U)` → `kappa_U` | `RootProvider::puf_eval()`（计数，非物理 PUF） | `src/root_provider.cpp` |
| `kappa_d = KDF(kappa_U; DOMAINROOT, d)` | `RootProvider::domain_root(d)` | `src/root_provider.cpp` |
| `Cert_Td = (d, ID, PK^LT, sigma_cert)`（式 (2)） | `CaCore::issue_cert()` / `CaCore::verify_cert()` | `src/protocol_core.cpp` |
| `PID_d = Hash(PID; d, eta_d)` | `derive_pid()` | `src/protocol_core.cpp` |

## 2. 逐消息映射

| 消息 | 公式 | 生成 | 处理 |
|---|---|---|---|
| `Authz^U_d=(ID_Td,e_d)` / `Authz^S_d=(PID,ID_Td,e_d)` | Sec.V-B | `MobilityManager::authorize()`、`authz_u()`、`authz_s()` | `run_transaction()` / `prepare_authorization()`（`src/harness.cpp`） |
| `Transfer_d={d,PID,ID_Td,e_d,S^C,Pi}` | Sec.V-B | `SourceCore::build_transfer()` | `TargetCore::accept_transfer()` |
| `M0={d,SID,X_T,Cert,PreAuth}` | (5)(6) | `TargetCore::create_session()`：`SID←$16B`、`X_T=x_T·P`、`TCTX`、`PreAuth=Sign(H(PREAUTH;TCTX))` | `UavCore::handle_m0()`：验证证书 → 重构 `TCTX` → 验证 `PreAuth` |
| `M1={SID,rho^B,X_U,PK^N,sigma_U}` | (7)(8) | `UavCore::build_m1()`：**新授权触发一次 `puf_eval()`**；`CV^N=Hash(NEXT;rho^B,TCTX,X_U,v^N)`；`sk^N=H2S(KDF(kappa_d;AUTHKEY,d,PID,v^N,CV^N))`；`rho^N=Hash(STATE;d,PID,v^N,CV^N,PK^N)`；`delta_pend=Hash(PENDING;TCTX,rho^B,v^N,CV^N,PK^N)`；`TH_0/TH_1`；`sigma_U=Sign_{sk^B}(H(UAV-AUTH;TH_1))` | `TargetCore::handle_m1()`：守卫 → 分支判定 → 重算候选 → 验签（式 (9)） |
| `M2={SID,tau_T}` | (10)(11) | `TargetCore::handle_m1()`：`Z=ECDH`、`ACTX=Hash(ACTX;TCTX,rho^B)`、`PRK=HKDF-Extract`、`K^cf/K^cm/K^s`、`tau_T=MAC_{K^cf}(H(TARGET-CONFIRM;TH_1))`、`TH_2=Hash(TH2;TH_1,tau_T)` | `UavCore::handle_m2()`：验证 `tau_T` → `tau_C=MAC_{K^cm}(H(COMMIT;TH_2))` |
| `M3={SID,tau_C}` | (12)(13) | `UavCore::handle_m2()` | `TargetCore::handle_m3()`：守卫 → 验 `tau_C` → 原子提交 |

## 3. 三个持久化点

| 时刻 | 代码位置 | 存储 |
|---|---|---|
| 发 M2 **之前** | `TargetCore::handle_m1()` 末尾 `store_->save_pending()` + `save_session()` | `src/state_store.cpp`（SQLite，真实落盘） |
| 发 M3 **之前** | `UavCore::handle_m2()` 中 `save_uav()` | 同上 |
| 验 M3 **之后** | `TargetCore::handle_m3()` 原子 `save_committed()` + `save_pending(nullopt)` | 同上 |

崩溃恢复：`World::crash_restart()` 销毁全部角色对象后由 `UavCore::restore_from_store()` / `TargetCore::restore_from_store(sid)` 重建。

## 4. 四个分支

| 分支 | 判定代码 | 语义 |
|---|---|---|
| normal | `pi_ == nullopt && rho_base == S^C.rho` | 正常事务 |
| cached-retry | `s.m2_sent && cached_m1 == 收到的 M1 字节` | 同会话重传，**不重新 PUFEval、不重新签名** |
| M2Recover | `pi_ != nullopt && rho_base == S^C.rho` | 只替换 pending，**不推进 `S^C`** |
| M3Recover | `pi_ != nullopt && rho_base == Pi.next.rho` | 先提交已激活的旧 pending（一次 +1），再建新 pending |

拒绝路径（`old epoch`、`expired session`、`unknown SID`、`base rho not admissible`、`invalid UAV state signature`、`A-Retry: new-authorization recovery unsupported`）**均不改写 `S^C/Pi/Sess.st`**。

## 5. 不变量与计数器

- `invariants_hold(su, sc, pi)`：实现式 (16)(17) 与结构约束（`Pi.base.rho == S^C.rho`、`Pi.next.v == S^C.v+1`）。
- `OpCounters`（`include/uavma/crypto.h`）：`hash / mac / h2s / sign / verify / ecdh / puf` 原始计数，用于 S3 复核操作账本；**不做任何"凑数"映射**，映射关系在输出元数据中显式声明。
- 字节账本：`ByteAccount{body, encoded}` + 传输层 `kFrameHeaderBytes=5`；日志同时给出 `paper_reference`（`docs/field_ledger.md` 的设计预算），两者**分开列**，不合并。

## 6. 尚未实现（诚实边界）

- B-MES 外部主对照：**BLOCKED_SOURCE**（无原文）。
- ns-3/IoD-Sim 传输后端：`tests/test_ns3_transport.cpp` 在 IoD-Sim 未冻结前返回 `BLOCKED_ENV`。
- 软件根提供者的运行时间**不等于**物理 PUF 读数（`Tpuf` 保持符号化）。
