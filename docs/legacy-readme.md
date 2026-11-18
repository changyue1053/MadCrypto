# IMCrypto — 企业 IM 双轨加密内核（Rust）

密聊轨（真端到端加密）的协议内核实现。设计依据见 [`../imcrypto-architecture.html`](../imcrypto-architecture.html)，
交付路线见 [`../imcrypto-implementation-plan.html`](../imcrypto-implementation-plan.html)。与 IMLink（长连接）、
IMDB（存储）同构成三内核家族。

## 现状

本仓库落地了实施计划 **P0 上线基线**的协议核心与企业侧：PQXDH 形态握手（v1.0 以 X3DH
退化态运行，ML-KEM 汇合点已留）、双棘轮、Sender Keys 群密聊 + GroupProtocol 编排
（MLS 可替换缝）、Sesame 多设备 + 每设备 pairwise 路由编排（P5 回填）、普通轨信封原语
（crypto-shredding）、企业 PKI + 证书吊销 CRL（P7 回填，消灭 TOFU 与"离职复活"）、
真 KT（Merkle 账本 + 签名树头 + 监控锚点，P7 回填）、策略引擎与防降级、C ABI 骨架
（panic 防火墙），以及贯穿全部的「解密即事务」崩溃一致性。

- **95 个测试全绿**（66 核心单元 + 3 条 proptest 属性×64 随机剧本 + **协议 DST 千种子** +
  8 FFI（含**真 clang 编译的 C ABI 往返冒烟**）+ 3 **真 SQLCipher 持久化**（含真库崩溃回滚）+
  10 原语/RFC 向量 + 4 国密 spike），`cargo clippy -D warnings` 零告警，
  协议层 `#![forbid(unsafe_code)]`（unsafe 全 workspace 仅 FFI 边界拷贝与裸指针解引用）。
- **端到端可持久化**：会话状态字节序列化 → 真 SQLCipher 事务落库（`BEGIN IMMEDIATE`）→
  掉电 WAL 回滚——"解密即事务"从 mock 证明升级为真加密数据库里的机械事实。
- **官方向量逐字节对齐**：RFC 7748（X25519）/ RFC 8032（Ed25519）/ RFC 5869（HKDF）/
  FIPS SHA-256 / McGrew–Viega AES-256-GCM——红灯不可 override。
- **协议 DST 千种子零违例**（release 实跑 0.43s）：随机操作流 ×（乱序交付 / 提交前掉电 /
  重放 / 重启）× 四不变量；任一失败种子 `IMCRYPTO_DST_SEED=<n>` 一键复现。
- 原语只用被审计的实现（RustCrypto / dalek），**不发明密码学**（架构 §1/§14）。
- `cargo run -p imcrypto-cli`：四幕叙事演示（握手 / 棘轮 / 掉电恢复 / 群踢人轮换）。

## 结构

```
crates/
├── imcrypto-prims/     # 原语层：CipherSuite trait + 国际套件（国密位留双后端）
│   ├── suite.rs        #   六能力抽象（DH/签名/AEAD/HKDF/hash/RNG），SuiteId 防降级
│   └── intl.rs         #   X25519 / Ed25519 / AES-256-GCM / HKDF-SHA-256
└── imcrypto-core/      # 协议层（纯 Rust）
    ├── keys.rs         #   密钥 newtype 纪律：!Clone / Zeroize / Debug 打码 / 常时比较
    ├── kdf.rs          #   HKDF 域分隔（label 常量表）
    ├── error.rs        #   五类错误 = 五种恢复动作
    ├── x3dh.rs         #   PQXDH 形态握手（bundle / DH₁₋₄ / OPK 语义 / 汇合点）
    ├── ratchet.rs      #   双棘轮（FS/PCS + skipped keys + 事务性解密）
    ├── group.rs        #   Sender Keys 群密聊 + GroupProtocol trait（六动作抽象，MLS 缝）
    ├── sesame.rs       #   多设备：签名设备表（防影子设备/防回滚）+ 撤销 + 扇出计划
    ├── router.rs       #   每设备 pairwise 路由：就地 X3DH · 撤销剔除存量会话 · 历史直传待办
    ├── session.rs      #   会话组装 + SessionStore 契约 + 解密即事务（崩溃一致性）
    ├── cloud.rs        #   普通轨信封原语：AAD 绑定 + 密钥版本 + crypto-shredding
    ├── pki.rs          #   企业 PKI：工牌证书 + 吊销列表 CRL（版本单调防回滚）——消灭 TOFU
    ├── kt.rs           #   密钥透明度【真实现】：签名树头 + 证明包 + 监控锚点 + 三层编排
    ├── merkle.rs       #   RFC 6962 形态 Merkle 日志：包含/一致性证明 + 无账本验证器
    ├── policy.rs       #   租户策略闸门 + 规范 AD 构造（轨道/套件/TTL 防降级）
    └── wire.rs         #   线格式编解码：带界游标 + 长度上限，decode(任意字节) 永不 panic
crates/imcrypto-ffi/    # C ABI：panic 防火墙 + selftest + 完整会话句柄面（唯一 unsafe 区）
    ├── handles.rs      #   identity/bundle/initiate/accept/encrypt/decrypt + pending-take 两段式
    ├── include/imcrypto.h  # 手写 C 头（由 build.rs 用真 clang 编译 tests/c_smoke.c 验证一致）
    └── build.rs        #   cc 编译 C 冒烟链接进 crate → 消除"头从未被 C 编译器验证"盲区
crates/imcrypto-store/  # 持久化后端：SQLCipher 真事务实现 SessionStore（解密即事务落地验证）
tools/
└── imcrypto-cli/       # 叙事式演示：握手 / 乱序与篡改 / 掉电恢复与幂等 / 群踢人轮换 / KT
```

## 模块 ↔ 架构章节

| 模块 | 架构章节 | 落地要点 |
|---|---|---|
| `prims/suite` | §3 §5 | CipherSuite 抽象；SuiteId 进 AAD 防降级；国密双后端预留 |
| `keys` | §14 | 私钥不可复制、离开作用域擦除、tag 常时比较——由类型强制 |
| `kdf` | §14 | 全部派生带 label 域分隔，跨上下文密钥重用在入口灭绝 |
| `x3dh` | §6 §19 | 离线建密；PQ 路缺席即 X3DH，打开 KEM 即 PQXDH（零重构） |
| `ratchet` | §7 | 前向保密 + 后向自愈；**篡改消息不推进状态**（事务性） |
| `group` | §8 §9 | O(1) 发送、O(N²) 轮换；持链密钥者也无法冒名（签名认证）；GroupProtocol 六动作 = MLS 可替换缝 |
| `sesame` | §10 | 设备表由身份签名背书、版本单调防回滚；撤销即刻剔除扇出（MDM 离职收权语义） |
| `router` | §10 | 扇出加密（每设备独立棘轮、缺会话就地 X3DH、首包随信封）；撤销收口存量会话；新设备结构性读不到历史 + 历史直传待办清单 |
| `session` | §1 §15 | 解密即事务：崩溃前不丢消息、崩溃后不二次消耗密钥；会话状态字节序列化 |
| `imcrypto-store` | §15 | SQLCipher 真事务实现 SessionStore；密钥自检先行；真库掉电 WAL 回滚 |
| `cloud` | §4 | 每消息 DEK 派生、密文跨会话/租户移植必败；销毁版本密钥 = 全部副本作废（合规删除） |
| `pki` | §11 | 工牌证书绑定 bundle 身份，目录发假钥被拦；CRL 签名背书 + 版本 pin——TOFU 与"重放旧列表复活离职者"都不存在 |
| `kt` + `merkle` | §11 | **真 KT**：STH 签名 + 包含证明客户端独立验证 + 监控锚点沿一致性证明前进——改写历史/树头回缩/静默换钥全部必被识破；换钥唯一合法路径是追加（留痕） |
| `policy` | §12 §13 | 密聊开关/角色黑名单/套件强制/群上限（租户配置）；轨道/套件/TTL 进 AD |
| `imcrypto-ffi` | §14 | panic 防火墙（捕获→错误码，abort 交宿主）；完整会话句柄面（C ABI 驱动密聊全流程）；密钥无任何序列化出口；pending-take 两段式取字节（状态推进不可重放） |

## 测试清单（关键不变量）

- **原语**：DH 双向一致、签名防篡改、AEAD 的 AAD 绑定（跨会话移植密文失败）、KDF 域分隔。
- **握手**：Alice/Bob 同 root、无 OPK 路径、假签名/套件不符/OPK 消费失败全拒。
- **双棘轮**：双向自愈、乱序 skipped keys、**篡改不失步**、错 AD 拒绝、超限跳过 DoS 护栏。
- **群密聊**：分发解密、乱序、**冒名拒绝**、轮换令旧接收态失效；编排层：三人全网状、
  踢人轮换锁死被踢者、新人结构性读不到历史。
- **多设备**：影子设备注入拒绝、版本回滚拒绝、撤销设备即刻从扇出计划剔除。
- **路由编排**：扇出 pairwise（同明文不同设备密文不同）、首包建会话、撤销剔除存量会话、
  新设备无历史信封 + 直传待办、缺首包头显式拒绝。
- **KT/Merkle**：包含与一致性证明全尺寸穷举、证明篡改/增删元素全拒、树头签名伪造拒绝、
  同密钥日志方改写历史被监控锚点识破、树头回缩拒绝、换钥留痕（登记次数）。
- **PKI/CRL**：伪造 CA / 篡改吊销列表拒绝、被吊销主体握手即拒、CRL 版本回滚拒绝、
  编排层"离职收权"端到端。
- **解密即事务**：提交前崩溃消息不丢、提交后重放幂等跳过、反证「无幂等则重放必失步」。
- **属性测试（proptest）**：双向会话任意轮次×任意乱序×重放注入全部收敛；单向 30 条全排列；
  群任意乱序 + 轮换语义。失败自动最小化。
- **协议 DST**（`tests/dst.rs`）：种子驱动 40 步随机操作流（发送 35% / 乱序交付 30% /
  提交前掉电 10% / 重放 10% / 重启 15%），四不变量——不丢不重 / 掉电重推可解 /
  重放幂等 / 任意重启后收敛；失败输出操作日志 + 种子号。
- **线格式**：每个截断点报 Malformed、1 万随机字节 + 逐字节变异不 panic、4GB 长度诈骗拦截。

## 运行

```bash
cargo test --workspace                       # 86 测试（+2 项国密压测 --ignored）
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release                        # 发布 profile：LTO + panic=abort + strip
cargo deny check                             # 供应链门禁（需 cargo-deny）
```

## 尚未落地（对应实施计划后续阶段）

诚实标注边界（架构 §17「设计期承诺，上线前回填」）：

- ~~P5 残余~~ **已回填**（`router.rs`）：pairwise 路由编排、撤销收口、历史直传**待办清单**；
  待办的搬运（老设备重新加密直传）走业务消息通道，属上层编排。
- ~~P7 残余~~ **已回填**（`merkle.rs` + `kt.rs` + `pki.rs` CRL）：真 Merkle 证明、签名树头、
  监控锚点、CRL 签发/验签/版本 pin。剩余：CRL 与设备表经 MDM 通道的**下发运维**（产品侧）。
- **P8 残余**：会话句柄面 + C ABI 冒烟 + 会话序列化 + 真 SQLCipher 持久化均已落地；
  待补 UniFFI/NAPI 绑定、Keychain/Keystore/HUKS 平台密钥真实现、NSE 剧本（需真机工具链）。
- **国密（P0.3 spike 已执行，决策门①正式结论，实测见 `prims/tests/sm_spike.rs`）**：
  - 可直接用：SM3（国标向量对齐）、SM2 签名/验签、**SM4-GCM 原生存在**（推翻"需自行
    组合"的纸面风险，R1 降级）；适配点：libsm 强制 16B IV（本库 nonce 约定 12B）。
  - 真缺口：SM2 密钥交换是四步交互式协议（GB/T 32918.3），与 X3DH 的非交互 raw DH
    **不同构**，且 libsm 0.6.1 无协商密钥 getter；debug 下单次交换 ~17s（BigUint 无优化）。
  - 结论：国密握手是**设计问题而非编码问题**（离线建密 × 交互式国标协议需方案评审）
    → 国密移 v1.1，v1.0 保持 `SuiteId::Sm` 接口位；铜锁认证模块对照随 v1.1 专项。
  - **可靠性补充发现**：全量并行测试中 libsm 出现过一次未复现失败（复跑 ×7 +
    release 压测 2×200 轮零复现，复现工具 `prims/tests/sm_stress.rs`，`--ignored`）。
    spike 测试已按"安全断言不重试、上游 Err 伪影重试一次、Err/Ok(false) 统一算拒绝"
    加固——上游错误边界不整洁这一点，进一步坐实铜锁对照评估的必要性。
- **PQXDH 的 PQ 路**：汇合点与 bundle 字段已留，ML-KEM 接入待 P1（产品策略打开即启用）。
- **向量对齐残余**：原语层官方向量已装载（RFC/GCM 论文）；协议级 Signal 向量与
  Wycheproof 边角料全量装载待 P9 前补齐。
- **P9 残余**：DST 已达千种子（接收路径）；发送路径 outbox 语义、cargo-fuzz（libFuzzer）
  长跑、dudect 侧信道抽测、内存取证脚本待补。

`SessionStore` 的内存 mock 用于证明协议正确；生产后端是 imcrypto-store → IMDB 的同一 SQLCipher 事务。

