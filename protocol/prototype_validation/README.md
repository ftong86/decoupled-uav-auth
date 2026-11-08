# prototype_validation_v2

这是“协议状态机机制原型”，对应论文中的：

Transfer -> M0/PreAuth -> M1 -> pending -> M2 -> UAV activation -> M3 -> commit

实现的真实协议字段/约束包括：
- authorization epoch
- 128-bit SID
- TCTX
- committed state S^C = (v,CV,PK,rho)
- UAV active state S^U
- pending Pi = <base,next,delta,SID,e>
- session status Prepared/AwaitM3/Committed
- TH0/TH1/TH2
- target-confirm MAC
- commit MAC
- M3 commit checks: session state, SID, epoch, pending digest, MAC
- stale M3 fencing

重要：本程序不是论文完整密码学实现。
SHA-256/HMAC 是真实计算；PreAuth 和 UAV signature 在这里使用可验证的 transcript token 作为状态机占位，
因此本程序用于“机制/状态机验证”，不能写成完整 cryptographic prototype。

## Ubuntu/WSL 编译

sudo apt install -y build-essential cmake libssl-dev

mkdir -p build
cd build
cmake ..
cmake --build . -j

运行：
./prototype_validation_v2 100 500 1000

100/500/1000 仅用于程序自检，不是论文最终 W。

输出：
- clock_offset_full_protocol.csv
- stale_m3_fencing.csv
