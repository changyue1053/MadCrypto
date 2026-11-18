//! 群密聊 Sender Keys（架构 §8）。发一条 O(1)、踢一人 O(N²)。
//!
//! 每个成员一条"发送链"（对称棘轮）+ 一把签名密钥。入群时把 SenderKey 分发消息（SKDM）
//! 经 pairwise 密聊通道（P3/P4）发给每个群友，此后群播只加密一次。签名钥提供**群内认证**：
//! 持有 chain_key 的成员也无法冒名他人（架构 §8）。轮换（踢人/定期）= 换全新 SenderKey 重分发。

use std::collections::HashMap;

use madcrypto_prims::CipherSuite;
use rand_core::{CryptoRng, RngCore};

use crate::error::{CryptoError, Result};
use crate::kdf::kdf_sender;
use crate::keys::{ChainKey, MessageKey, SignPrivate, SignPublic};

const MAX_SKIP: u32 = 2000;

/// 群消息线格式：迭代号 + 密文 + 发送者签名。
pub struct GroupMessage {
    pub iteration: u32,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

/// SenderKey 分发消息（SKDM）：经 pairwise 密聊安全通道送达每个群友。
/// 携带**当前**链密钥快照 + 迭代号 + 签名公钥（接收方据此建立对该发送者的接收态）。
pub struct SenderKeyDistribution {
    pub chain_key: ChainKey,
    pub iteration: u32,
    pub signing_public: SignPublic,
}

/// 自己在某群里的发送态。
pub struct GroupSender {
    chain_key: ChainKey,
    signing_private: SignPrivate,
    signing_public: SignPublic,
    iteration: u32,
}

impl GroupSender {
    /// 建群/入群/轮换时生成全新 SenderKey（随机链密钥 + 新签名密钥对）。
    pub fn new<S: CipherSuite, R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut ck = [0u8; 32];
        rng.fill_bytes(&mut ck);
        let sig = S::sign_keypair(rng);
        let sender = Self {
            chain_key: ChainKey::new(ck),
            signing_private: SignPrivate::new(sig.private),
            signing_public: SignPublic::new(sig.public),
            iteration: 0,
        };
        ck.zeroize_local();
        sender
    }

    /// 生成分发消息（当前链密钥快照）——只应经加密的 pairwise 通道发送。
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            chain_key: self.chain_key.clone_secret(),
            iteration: self.iteration,
            signing_public: self.signing_public.clone(),
        }
    }

    /// 群播加密：对称棘轮前进一格 → 每消息独立密钥 + 发送者签名（群内认证）。
    pub fn encrypt<S: CipherSuite>(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<GroupMessage> {
        let (next, mk) = kdf_sender::<S>(&self.chain_key);
        self.chain_key = next;
        let iteration = self.iteration;
        self.iteration += 1;

        let aad = aead_ad(ad, iteration);
        let ct = S::aead_seal(mk.key(), mk.iv(), &aad, plaintext);
        let signature = S::sign(self.signing_private.expose(), &signed_bytes(ad, iteration, &ct))?;
        Ok(GroupMessage {
            iteration,
            ciphertext: ct,
            signature,
        })
    }
}

/// 对某个发送者的接收态（每个群友对每个其他成员各持一份）。
pub struct GroupReceiver {
    chain_key: Option<ChainKey>,
    signing_public: SignPublic,
    iteration: u32,
    skipped: HashMap<u32, MessageKey>,
}

impl GroupReceiver {
    pub fn from_distribution(d: SenderKeyDistribution) -> Self {
        Self {
            chain_key: Some(d.chain_key),
            signing_public: d.signing_public,
            iteration: d.iteration,
            skipped: HashMap::new(),
        }
    }

    /// 群消息解密（事务性）：先验签（群内认证），再在副本上试算，成功才提交。
    pub fn decrypt<S: CipherSuite>(&mut self, ad: &[u8], msg: &GroupMessage) -> Result<Vec<u8>> {
        // 群内认证优先：持有链密钥的成员也无法冒名（架构 §8）
        if !S::verify(
            self.signing_public.as_slice(),
            &signed_bytes(ad, msg.iteration, &msg.ciphertext),
            &msg.signature,
        ) {
            return Err(CryptoError::Handshake("群消息签名非法（冒名）"));
        }

        let mut trial = self.dup();
        let plaintext = trial.decrypt_inplace::<S>(ad, msg)?;
        *self = trial;
        Ok(plaintext)
    }

    fn decrypt_inplace<S: CipherSuite>(&mut self, ad: &[u8], msg: &GroupMessage) -> Result<Vec<u8>> {
        let aad = aead_ad(ad, msg.iteration);

        // 早到消息之前的迭代：要么命中跳过缓存，要么是重放
        if msg.iteration < self.iteration {
            let mk = self
                .skipped
                .remove(&msg.iteration)
                .ok_or(CryptoError::DecryptDesync)?;
            return S::aead_open(mk.key(), mk.iv(), &aad, &msg.ciphertext)
                .map_err(|_| CryptoError::DecryptDesync);
        }

        // 补齐 [iteration, msg.iteration) 到跳过缓存（乱序容忍 + DoS 护栏）
        if self.iteration.saturating_add(MAX_SKIP) < msg.iteration {
            return Err(CryptoError::DecryptRetryable);
        }
        while self.iteration < msg.iteration {
            let ck = self.chain_key.take().ok_or(CryptoError::StateCorrupt)?;
            let (next, mk) = kdf_sender::<S>(&ck);
            self.chain_key = Some(next);
            self.skipped.insert(self.iteration, mk);
            self.iteration += 1;
        }

        // 派生当前迭代密钥并解密
        let ck = self.chain_key.take().ok_or(CryptoError::DecryptDesync)?;
        let (next, mk) = kdf_sender::<S>(&ck);
        self.chain_key = Some(next);
        self.iteration += 1;
        S::aead_open(mk.key(), mk.iv(), &aad, &msg.ciphertext).map_err(|_| CryptoError::DecryptDesync)
    }

    fn dup(&self) -> Self {
        let mut skipped = HashMap::with_capacity(self.skipped.len());
        for (k, v) in &self.skipped {
            skipped.insert(*k, v.clone_secret());
        }
        Self {
            chain_key: self.chain_key.as_ref().map(ChainKey::clone_secret),
            signing_public: self.signing_public.clone(),
            iteration: self.iteration,
            skipped,
        }
    }
}

// ============================================================================
// GroupProtocol：架构 §9 的「MLS 可替换缝」——六动作抽象，Sender Keys 是第一个实现。
//
// 走查标准（实施 P6.5 DoD）：接口不泄漏 sender-key 专有概念。对照 MLS 语义：
// create→建群+Welcome；on_member_added→Add+Welcome；on_member_removed→Remove+Commit；
// rotate→Update Commit；install→处理 Welcome/Commit；encrypt/decrypt→应用消息。
// ============================================================================

/// 成员标识。生产中为（user_id, device_id）——Sesame 扇出按设备粒度（架构 §10）。
pub type MemberId = String;

/// 成员事件产出的编排动作：把密钥材料经 pairwise 密聊通道发给谁（架构 §8 分发）。
pub struct DistributionTask {
    pub to: MemberId,
    pub distribution: SenderKeyDistribution,
}

/// 群密聊协议抽象（六动作）。换协议（MLS）= 换一个实现，编排层与业务不动（架构 §9）。
pub trait GroupProtocol: Sized {
    /// 建群：生成本端发送态，产出给初始成员的分发任务。
    fn create<S: CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
        members: &[MemberId],
    ) -> (Self, Vec<DistributionTask>);

    /// 新成员入群：向新人分发本端密钥材料（O(1) 任务；新人自己 create 后向全员分发）。
    /// 结构性保证：分发携带的是**当前**链快照——新人读不到历史（架构 §8）。
    fn on_member_added<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        member: &MemberId,
    ) -> Vec<DistributionTask>;

    /// 成员被移除：丢弃其接收态 + 轮换本端密钥并向存量成员重发。
    /// 全员各自执行本动作 = O(N²) 条分发消息——500 人上限的根源（架构 §8/§9）。
    fn on_member_removed<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        removed: &MemberId,
        remaining: &[MemberId],
    ) -> Vec<DistributionTask>;

    /// 定期轮换（7 天 / 1000 条，架构 §8 对群 PCS 的补偿）。
    fn rotate<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        members: &[MemberId],
    ) -> Vec<DistributionTask>;

    /// 安装来自某成员的密钥材料（经 pairwise 通道收到的 SKDM / MLS Welcome）。
    fn install(&mut self, from: MemberId, distribution: SenderKeyDistribution);

    fn encrypt<S: CipherSuite>(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<GroupMessage>;
    fn decrypt<S: CipherSuite>(
        &mut self,
        from: &MemberId,
        ad: &[u8],
        msg: &GroupMessage,
    ) -> Result<Vec<u8>>;
}

/// Sender Keys 实现：自己的发送态 + 对每个成员的接收态。
pub struct SenderKeyGroup {
    sender: GroupSender,
    receivers: HashMap<MemberId, GroupReceiver>,
}

impl SenderKeyGroup {
    fn tasks_for(&self, members: &[MemberId]) -> Vec<DistributionTask> {
        members
            .iter()
            .map(|m| DistributionTask {
                to: m.clone(),
                distribution: self.sender.distribution(),
            })
            .collect()
    }
}

impl GroupProtocol for SenderKeyGroup {
    fn create<S: CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
        members: &[MemberId],
    ) -> (Self, Vec<DistributionTask>) {
        let group = Self {
            sender: GroupSender::new::<S, R>(rng),
            receivers: HashMap::new(),
        };
        let tasks = group.tasks_for(members);
        (group, tasks)
    }

    fn on_member_added<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        member: &MemberId,
    ) -> Vec<DistributionTask> {
        self.tasks_for(std::slice::from_ref(member))
    }

    fn on_member_removed<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        removed: &MemberId,
        remaining: &[MemberId],
    ) -> Vec<DistributionTask> {
        self.receivers.remove(removed);
        self.rotate::<S, R>(rng, remaining)
    }

    fn rotate<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        members: &[MemberId],
    ) -> Vec<DistributionTask> {
        // 轮换 = 全新 SenderKey（新链 + 新签名钥）：被移除者手里的旧材料即刻作废
        self.sender = GroupSender::new::<S, R>(rng);
        self.tasks_for(members)
    }

    fn install(&mut self, from: MemberId, distribution: SenderKeyDistribution) {
        self.receivers
            .insert(from, GroupReceiver::from_distribution(distribution));
    }

    fn encrypt<S: CipherSuite>(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<GroupMessage> {
        self.sender.encrypt::<S>(ad, plaintext)
    }

    fn decrypt<S: CipherSuite>(
        &mut self,
        from: &MemberId,
        ad: &[u8],
        msg: &GroupMessage,
    ) -> Result<Vec<u8>> {
        self.receivers
            .get_mut(from)
            .ok_or(CryptoError::Handshake("未知发送者（未收到其密钥分发）"))?
            .decrypt::<S>(ad, msg)
    }
}

fn aead_ad(ad: &[u8], iteration: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(ad.len() + 4);
    v.extend_from_slice(ad);
    v.extend_from_slice(&iteration.to_be_bytes());
    v
}

fn signed_bytes(ad: &[u8], iteration: u32, ct: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ad.len() + 4 + ct.len());
    v.extend_from_slice(ad);
    v.extend_from_slice(&iteration.to_be_bytes());
    v.extend_from_slice(ct);
    v
}

// 局部密钥缓冲擦除的小工具（[u8;32] 非 Drop-zeroize）。
trait ZeroizeLocal {
    fn zeroize_local(&mut self);
}
impl ZeroizeLocal for [u8; 32] {
    fn zeroize_local(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    const AD: &[u8] = b"group:eng-all";

    #[test]
    fn distribute_then_members_decrypt() {
        let mut rng = ChaCha20Rng::seed_from_u64(20);
        let mut alice = GroupSender::new::<S, _>(&mut rng);
        // Bob、Carol 各自从 Alice 的 SKDM 建立接收态
        let mut bob = GroupReceiver::from_distribution(alice.distribution());
        let mut carol = GroupReceiver::from_distribution(alice.distribution());

        let m = alice.encrypt::<S>(AD, b"standup at 10").unwrap();
        assert_eq!(bob.decrypt::<S>(AD, &m).unwrap(), b"standup at 10");
        assert_eq!(carol.decrypt::<S>(AD, &m).unwrap(), b"standup at 10");
    }

    #[test]
    fn out_of_order_group_messages() {
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let mut alice = GroupSender::new::<S, _>(&mut rng);
        let mut bob = GroupReceiver::from_distribution(alice.distribution());
        let m0 = alice.encrypt::<S>(AD, b"g0").unwrap();
        let m1 = alice.encrypt::<S>(AD, b"g1").unwrap();
        let m2 = alice.encrypt::<S>(AD, b"g2").unwrap();
        // 乱序：先 m2（跳过 0,1），再 m0、m1
        assert_eq!(bob.decrypt::<S>(AD, &m2).unwrap(), b"g2");
        assert_eq!(bob.decrypt::<S>(AD, &m0).unwrap(), b"g0");
        assert_eq!(bob.decrypt::<S>(AD, &m1).unwrap(), b"g1");
    }

    #[test]
    fn impersonation_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(22);
        let mut alice = GroupSender::new::<S, _>(&mut rng);
        let eve = GroupSender::new::<S, _>(&mut rng); // 冒充者另有一把签名钥
        let mut bob = GroupReceiver::from_distribution(alice.distribution());

        // 取 Alice 的真实消息，但把签名换成 Eve 用自己密钥重签 —— 冒名
        let mut m = alice.encrypt::<S>(AD, b"legit").unwrap();
        m.signature = S::sign(
            // 直接借用 Eve 的私钥重签同样的字节
            eve_signing_private(&eve),
            &signed_bytes(AD, m.iteration, &m.ciphertext),
        )
        .unwrap();
        let err = bob.decrypt::<S>(AD, &m).err().unwrap();
        assert_eq!(err, CryptoError::Handshake("群消息签名非法（冒名）"));
    }

    #[test]
    fn rotation_invalidates_old_distribution() {
        let mut rng = ChaCha20Rng::seed_from_u64(23);
        let mut alice = GroupSender::new::<S, _>(&mut rng);
        let mut bob_old = GroupReceiver::from_distribution(alice.distribution());
        let m_old = alice.encrypt::<S>(AD, b"before-kick").unwrap();
        assert_eq!(bob_old.decrypt::<S>(AD, &m_old).unwrap(), b"before-kick");

        // 踢人 → Alice 轮换全新 SenderKey（旧接收态对新消息不可解）
        alice = GroupSender::new::<S, _>(&mut rng);
        let m_new = alice.encrypt::<S>(AD, b"after-kick").unwrap();
        assert!(
            bob_old.decrypt::<S>(AD, &m_new).is_err(),
            "轮换后，旧分发建立的接收态必须无法解密新消息"
        );
    }

    // 测试辅助：借用 GroupSender 的签名私钥字节（仅测试用，模拟冒名者）
    fn eve_signing_private(s: &GroupSender) -> &[u8] {
        s.signing_private.expose()
    }

    // ---- GroupProtocol 编排层（实施 P6.3/P6.5）----

    fn m(s: &str) -> MemberId {
        s.to_string()
    }

    /// 全员互相安装分发任务（模拟 pairwise 通道送达）。
    fn deliver(tasks: Vec<DistributionTask>, from: &str, groups: &mut HashMap<MemberId, SenderKeyGroup>) {
        for t in tasks {
            if let Some(g) = groups.get_mut(&t.to) {
                g.install(m(from), t.distribution);
            }
        }
    }

    #[test]
    fn three_member_group_full_mesh() {
        let mut rng = ChaCha20Rng::seed_from_u64(30);
        let names = [m("alice"), m("bob"), m("carol")];
        let mut groups: HashMap<MemberId, SenderKeyGroup> = HashMap::new();
        let mut pending: Vec<(MemberId, Vec<DistributionTask>)> = Vec::new();

        for me in &names {
            let others: Vec<MemberId> = names.iter().filter(|n| *n != me).cloned().collect();
            let (g, tasks) = SenderKeyGroup::create::<S, _>(&mut rng, &others);
            groups.insert(me.clone(), g);
            pending.push((me.clone(), tasks));
        }
        for (from, tasks) in pending {
            deliver(tasks, &from, &mut groups);
        }

        // 每个成员发一条，其余成员都能解且验明正身
        for me in &names {
            let msg = groups.get_mut(me).unwrap().encrypt::<S>(AD, me.as_bytes()).unwrap();
            for other in names.iter().filter(|n| *n != me) {
                let pt = groups.get_mut(other).unwrap().decrypt::<S>(me, AD, &msg).unwrap();
                assert_eq!(pt, me.as_bytes());
            }
        }
    }

    #[test]
    fn kick_member_then_rotate_locks_them_out() {
        let mut rng = ChaCha20Rng::seed_from_u64(31);
        let (alice_n, bob_n, carol_n) = (m("alice"), m("bob"), m("carol"));
        let mut groups: HashMap<MemberId, SenderKeyGroup> = HashMap::new();

        let (ga, ta) = SenderKeyGroup::create::<S, _>(&mut rng, &[bob_n.clone(), carol_n.clone()]);
        let (gb, tb) = SenderKeyGroup::create::<S, _>(&mut rng, &[alice_n.clone(), carol_n.clone()]);
        let (gc, tc) = SenderKeyGroup::create::<S, _>(&mut rng, &[alice_n.clone(), bob_n.clone()]);
        groups.insert(alice_n.clone(), ga);
        groups.insert(bob_n.clone(), gb);
        groups.insert(carol_n.clone(), gc);
        deliver(ta, "alice", &mut groups);
        deliver(tb, "bob", &mut groups);
        deliver(tc, "carol", &mut groups);

        // 踢 carol：alice 与 bob 各自执行移除 + 轮换，重发给存量成员
        let remaining_for_alice = [bob_n.clone()];
        let ta2 = groups
            .get_mut(&alice_n)
            .unwrap()
            .on_member_removed::<S, _>(&mut rng, &carol_n, &remaining_for_alice);
        let remaining_for_bob = [alice_n.clone()];
        let tb2 = groups
            .get_mut(&bob_n)
            .unwrap()
            .on_member_removed::<S, _>(&mut rng, &carol_n, &remaining_for_bob);
        deliver(ta2, "alice", &mut groups);
        deliver(tb2, "bob", &mut groups);

        // 轮换后：bob 正常解，carol（还留着旧接收态）必不可解
        let msg = groups.get_mut(&alice_n).unwrap().encrypt::<S>(AD, b"post-kick").unwrap();
        assert_eq!(
            groups.get_mut(&bob_n).unwrap().decrypt::<S>(&alice_n, AD, &msg).unwrap(),
            b"post-kick"
        );
        assert!(
            groups.get_mut(&carol_n).unwrap().decrypt::<S>(&alice_n, AD, &msg).is_err(),
            "被踢成员对轮换后的消息必须不可解"
        );
    }

    #[test]
    fn late_joiner_cannot_read_history() {
        let mut rng = ChaCha20Rng::seed_from_u64(32);
        let (mut alice, _t) = SenderKeyGroup::create::<S, _>(&mut rng, &[m("bob")]);

        // 入群前的历史消息
        let history = alice.encrypt::<S>(AD, b"secret-history").unwrap();

        // dave 入群：拿到的是【当前】链快照（iteration 已前进）
        let tasks = alice.on_member_added::<S, _>(&mut rng, &m("dave"));
        let mut dave = SenderKeyGroup {
            sender: GroupSender::new::<S, _>(&mut rng),
            receivers: HashMap::new(),
        };
        for t in tasks {
            dave.install(m("alice"), t.distribution);
        }

        // 新消息可解，历史消息结构性不可解（链单向，推不回去）
        let fresh = alice.encrypt::<S>(AD, b"fresh").unwrap();
        assert_eq!(dave.decrypt::<S>(&m("alice"), AD, &fresh).unwrap(), b"fresh");
        assert!(
            dave.decrypt::<S>(&m("alice"), AD, &history).is_err(),
            "入群晚于消息发出的成员必须读不到历史（FS 白送，架构 §8）"
        );
    }
}

