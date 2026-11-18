//! 双棘轮（架构 §7）。对称棘轮给前向保密（FS），DH 棘轮给后向自愈（PCS）。
//!
//! 工程要点：**解密即事务**。一条伪造/篡改的消息绝不能推进棘轮状态——否则合法的
//! 下一条就解不开（失步）。实现方式：在状态副本上试算，AEAD 验证通过才 `*self = trial`
//! 提交；失败则副本丢弃、原状态分毫不动。这与跨内核的"解密即事务"（§15）是同一原则
//! 在棘轮层的体现。

use std::collections::HashMap;

use madcrypto_prims::CipherSuite;
use rand_core::{CryptoRng, RngCore};

use crate::error::{CryptoError, Result};
use crate::kdf::{kdf_ck, kdf_rk};
use crate::keys::{ChainKey, DhPrivate, DhPublic, MessageKey, RootKey};

/// 单条链最多允许跳过的消息数（架构 §7：skipped keys 上限，防 DoS）。
const MAX_SKIP: u32 = 2000;
/// 全部链累计缓存的跳过密钥上限（跨 DH 棘轮步的总量护栏）。
const MAX_SKIP_TOTAL: usize = 4000;

/// 消息头：驱动对端 DH 棘轮 + 定位消息序号。进 AEAD 关联数据，篡改即解密失败。
#[derive(Clone, Debug)]
pub struct Header {
    pub dh: DhPublic,
    pub pn: u32,
    pub n: u32,
}

impl Header {
    /// 线格式：pn(4) ‖ n(4) ‖ dh_len(2) ‖ dh。带长度前缀避免拼接歧义。
    pub fn encode(&self) -> Vec<u8> {
        let dh = self.dh.as_slice();
        let mut out = Vec::with_capacity(10 + dh.len());
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out.extend_from_slice(&(dh.len() as u16).to_be_bytes());
        out.extend_from_slice(dh);
        out
    }
}

/// 一条会话的双棘轮状态。`!Sync`（含 !Sync 的密钥），加解密由会话 Actor 串行（架构 §14）。
pub struct Ratchet {
    dhs_priv: DhPrivate,
    dhs_pub: DhPublic,
    dhr: Option<DhPublic>,
    rk: RootKey,
    cks: Option<ChainKey>,
    ckr: Option<ChainKey>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<(DhPublic, u32), MessageKey>,
}

impl Ratchet {
    /// 发起方（Alice）：root=SK，对端初始棘轮公钥=SPK_B，立即建立发送链（可先发）。
    pub fn init_initiator<S: CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
        root: RootKey,
        their_ratchet_public: DhPublic,
    ) -> Result<Self> {
        let kp = S::dh_keypair(rng);
        let dhs_priv = DhPrivate::new(kp.private);
        let dhs_pub = DhPublic::new(kp.public);
        let dh_out = S::dh(dhs_priv.expose(), their_ratchet_public.as_slice())?;
        let (rk, cks) = kdf_rk::<S>(&root, &dh_out);
        Ok(Self {
            dhs_priv,
            dhs_pub,
            dhr: Some(their_ratchet_public),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        })
    }

    /// 接收方（Bob）：root=SK，自己的初始棘轮密钥对=SPK_B，收到首条消息后才建立收发链。
    pub fn init_receiver(root: RootKey, my_private: DhPrivate, my_public: DhPublic) -> Self {
        Self {
            dhs_priv: my_private,
            dhs_pub: my_public,
            dhr: None,
            rk: root,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    pub fn sending_public(&self) -> &DhPublic {
        &self.dhs_pub
    }

    /// 加密一条消息：对称棘轮前进一格 → 每消息独立密钥 → 用后即毁（§7 前向保密）。
    pub fn encrypt<S: CipherSuite>(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<(Header, Vec<u8>)> {
        let ck = self
            .cks
            .take()
            .ok_or(CryptoError::Handshake("发送链未就绪（接收方需先收一条）"))?;
        let (next_ck, mk) = kdf_ck::<S>(&ck);
        self.cks = Some(next_ck);

        let header = Header {
            dh: self.dhs_pub.clone(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let aad = with_header(ad, &header);
        let ct = S::aead_seal(mk.key(), mk.iv(), &aad, plaintext);
        Ok((header, ct))
    }

    /// 解密一条消息（事务性）：在副本上试算，成功才提交。
    pub fn decrypt<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        header: &Header,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>> {
        let mut trial = self.dup();
        let plaintext = trial.decrypt_inplace::<S, R>(rng, header, ciphertext, ad)?;
        *self = trial; // 仅在成功时提交
        Ok(plaintext)
    }

    // ---- 内部：非事务的原始算法，只在副本上跑 ----

    fn decrypt_inplace<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        header: &Header,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>> {
        // 1) 命中已跳过的密钥（乱序早到的消息）
        let sk_key = (header.dh.clone(), header.n);
        if let Some(mk) = self.skipped.remove(&sk_key) {
            let aad = with_header(ad, header);
            return S::aead_open(mk.key(), mk.iv(), &aad, ciphertext).map_err(|_| CryptoError::DecryptDesync);
        }

        // 2) 新的棘轮公钥 → 先补齐当前接收链到 pn，再做 DH 棘轮
        if self.dhr.as_ref() != Some(&header.dh) {
            self.skip_message_keys::<S>(header.pn)?;
            self.dh_ratchet::<S, R>(rng, header)?;
        }

        // 3) 在（新）接收链上补齐到 n
        self.skip_message_keys::<S>(header.n)?;

        // 4) 派生本条消息密钥并解密
        let ck = self.ckr.take().ok_or(CryptoError::DecryptDesync)?;
        let (next_ck, mk) = kdf_ck::<S>(&ck);
        self.ckr = Some(next_ck);
        self.nr += 1;

        let aad = with_header(ad, header);
        S::aead_open(mk.key(), mk.iv(), &aad, ciphertext).map_err(|_| CryptoError::DecryptDesync)
    }

    fn skip_message_keys<S: CipherSuite>(&mut self, until: u32) -> Result<()> {
        if self.ckr.is_none() {
            return Ok(());
        }
        // DoS 护栏：拒绝派生超过上限的跳过密钥（架构 §7）
        if self.nr.saturating_add(MAX_SKIP) < until {
            return Err(CryptoError::DecryptRetryable);
        }
        while self.nr < until {
            if self.skipped.len() >= MAX_SKIP_TOTAL {
                return Err(CryptoError::DecryptRetryable);
            }
            let ck = self.ckr.take().ok_or(CryptoError::StateCorrupt)?;
            let (next_ck, mk) = kdf_ck::<S>(&ck);
            self.ckr = Some(next_ck);
            let dhr = self.dhr.clone().ok_or(CryptoError::StateCorrupt)?;
            self.skipped.insert((dhr, self.nr), mk);
            self.nr += 1;
        }
        Ok(())
    }

    fn dh_ratchet<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        header: &Header,
    ) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh.clone());

        // 接收链：DH(我方当前私钥, 对方新公钥)
        let dh_recv = S::dh(self.dhs_priv.expose(), header.dh.as_slice())?;
        let (rk1, ckr) = kdf_rk::<S>(&self.rk, &dh_recv);
        self.rk = rk1;
        self.ckr = Some(ckr);

        // 生成我方新棘轮密钥对，建立新的发送链
        let kp = S::dh_keypair(rng);
        self.dhs_priv = DhPrivate::new(kp.private);
        self.dhs_pub = DhPublic::new(kp.public);
        let dh_send = S::dh(self.dhs_priv.expose(), header.dh.as_slice())?;
        let (rk2, cks) = kdf_rk::<S>(&self.rk, &dh_send);
        self.rk = rk2;
        self.cks = Some(cks);
        Ok(())
    }

    /// 序列化为字节 blob（§15：落库的会话状态本体）。确定性：skipped 按 (dh, n) 排序。
    ///
    /// 格式：`[ver=1][dhs_priv:lv16][dhs_pub:lv16][dhr:opt-lv16][rk:32][cks:opt-32][ckr:opt-32]`
    ///       `[ns:4][nr:4][pn:4][skip_count:4]{[dh:lv16][n:4][mk_key:32][mk_iv:12]}*`
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.skipped.len() * 80);
        out.push(1);
        crate::wire::put16(&mut out, self.dhs_priv.expose());
        crate::wire::put16(&mut out, self.dhs_pub.as_slice());
        match &self.dhr {
            Some(p) => {
                out.push(1);
                crate::wire::put16(&mut out, p.as_slice());
            }
            None => out.push(0),
        }
        out.extend_from_slice(self.rk.expose());
        put_opt32(&mut out, self.cks.as_ref());
        put_opt32(&mut out, self.ckr.as_ref());
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.nr.to_be_bytes());
        out.extend_from_slice(&self.pn.to_be_bytes());

        let mut entries: Vec<(&DhPublic, &u32, &MessageKey)> =
            self.skipped.iter().map(|((d, n), mk)| (d, n, mk)).collect();
        entries.sort_by(|a, b| a.0.as_slice().cmp(b.0.as_slice()).then(a.1.cmp(b.1)));
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (dh, n, mk) in entries {
            crate::wire::put16(&mut out, dh.as_slice());
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(mk.key());
            out.extend_from_slice(mk.iv());
        }
        out
    }

    /// 从字节 blob 恢复（§15：崩溃后从存储重建会话）。带界解码，任意坏字节报 StateCorrupt。
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut c = crate::wire::Cursor::new(bytes);
        let bad = |_| CryptoError::StateCorrupt;
        if c.u8().map_err(bad)? != 1 {
            return Err(CryptoError::StateCorrupt);
        }
        let dhs_priv = DhPrivate::new(c.lv16().map_err(bad)?.to_vec());
        let dhs_pub = DhPublic::new(c.lv16().map_err(bad)?.to_vec());
        let dhr = match c.u8().map_err(bad)? {
            0 => None,
            1 => Some(DhPublic::new(c.lv16().map_err(bad)?.to_vec())),
            _ => return Err(CryptoError::StateCorrupt),
        };
        let rk = RootKey::new(c.arr32().map_err(bad)?);
        let cks = take_opt32(&mut c)?.map(ChainKey::new);
        let ckr = take_opt32(&mut c)?.map(ChainKey::new);
        let ns = c.u32().map_err(bad)?;
        let nr = c.u32().map_err(bad)?;
        let pn = c.u32().map_err(bad)?;
        let count = c.u32().map_err(bad)?;
        let mut skipped = HashMap::with_capacity(count as usize);
        for _ in 0..count {
            let dh = DhPublic::new(c.lv16().map_err(bad)?.to_vec());
            let n = c.u32().map_err(bad)?;
            let key = c.arr32().map_err(bad)?;
            let iv: [u8; 12] = c.take(12).map_err(bad)?.try_into().expect("定长");
            skipped.insert((dh, n), MessageKey::new(key, iv));
        }
        c.finish().map_err(bad)?;
        Ok(Self {
            dhs_priv,
            dhs_pub,
            dhr,
            rk,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
        })
    }

    /// 受控深拷贝：事务性解密的副本机制（见模块头）+ 会话快照落库（§15）。仅 crate 内使用。
    pub(crate) fn dup(&self) -> Self {
        let mut skipped = HashMap::with_capacity(self.skipped.len());
        for (k, v) in &self.skipped {
            skipped.insert(k.clone(), v.clone_secret());
        }
        Self {
            dhs_priv: self.dhs_priv.clone_secret(),
            dhs_pub: self.dhs_pub.clone(),
            dhr: self.dhr.clone(),
            rk: self.rk.clone_secret(),
            cks: self.cks.as_ref().map(ChainKey::clone_secret),
            ckr: self.ckr.as_ref().map(ChainKey::clone_secret),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped,
        }
    }
}

fn put_opt32(out: &mut Vec<u8>, ck: Option<&ChainKey>) {
    match ck {
        Some(c) => {
            out.push(1);
            out.extend_from_slice(c.expose());
        }
        None => out.push(0),
    }
}

fn take_opt32(c: &mut crate::wire::Cursor<'_>) -> Result<Option<[u8; 32]>> {
    let bad = |_| CryptoError::StateCorrupt;
    match c.u8().map_err(bad)? {
        0 => Ok(None),
        1 => Ok(Some(c.arr32().map_err(bad)?)),
        _ => Err(CryptoError::StateCorrupt),
    }
}

fn with_header(ad: &[u8], header: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ad.len() + 16);
    aad.extend_from_slice(ad);
    aad.extend_from_slice(&header.encode());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::{generate_identity, initiate, new_signed_prekey, respond, PreKeyBundle, ResponderKeys};
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    const AD: &[u8] = b"conv:42|alice<->bob";

    /// 建立一对已握手的棘轮（Alice initiator / Bob receiver），复用 P3 的 X3DH。
    fn established(seed: u64) -> (Ratchet, Ratchet, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let alice_id = generate_identity::<S, _>(&mut rng);
        let bob_id = generate_identity::<S, _>(&mut rng);
        let (spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(&mut rng, &bob_id).unwrap();
        let bundle = PreKeyBundle {
            suite: S::id(),
            identity: bob_id.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };
        let init = initiate::<S, _>(&mut rng, &alice_id, &bundle).unwrap();
        let resp = respond::<S>(
            ResponderKeys {
                identity: &bob_id,
                signed_prekey_private: &spk_priv,
                one_time_prekey_private: None,
            },
            &init.initial_message,
        )
        .unwrap();
        let alice = Ratchet::init_initiator::<S, _>(&mut rng, init.root, init.their_ratchet_public).unwrap();
        let bob = Ratchet::init_receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public);
        (alice, bob, rng)
    }

    #[test]
    fn in_order_roundtrip_both_directions() {
        let (mut alice, mut bob, mut rng) = established(10);
        // Alice → Bob
        let (h, ct) = alice.encrypt::<S>(AD, b"hello bob").unwrap();
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), b"hello bob");
        // Bob → Alice（触发 Alice 侧 DH 棘轮）
        let (h2, ct2) = bob.encrypt::<S>(AD, b"hi alice").unwrap();
        assert_eq!(alice.decrypt::<S, _>(&mut rng, &h2, &ct2, AD).unwrap(), b"hi alice");
        // 再来一轮，确认棘轮持续自愈
        let (h3, ct3) = alice.encrypt::<S>(AD, b"round two").unwrap();
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h3, &ct3, AD).unwrap(), b"round two");
    }

    #[test]
    fn out_of_order_delivery_uses_skipped_keys() {
        let (mut alice, mut bob, mut rng) = established(11);
        let (h0, c0) = alice.encrypt::<S>(AD, b"m0").unwrap();
        let (h1, c1) = alice.encrypt::<S>(AD, b"m1").unwrap();
        let (h2, c2) = alice.encrypt::<S>(AD, b"m2").unwrap();
        // Bob 先收到 m2（跳过 0,1），再收 m0、m1
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h2, &c2, AD).unwrap(), b"m2");
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h0, &c0, AD).unwrap(), b"m0");
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h1, &c1, AD).unwrap(), b"m1");
    }

    #[test]
    fn tampered_ciphertext_does_not_desync_state() {
        let (mut alice, mut bob, mut rng) = established(12);
        let (h0, c0) = alice.encrypt::<S>(AD, b"legit-0").unwrap();
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h0, &c0, AD).unwrap(), b"legit-0");

        // 伪造消息：篡改密文。解密必失败，且【状态不得推进】（事务性）
        let (h1, c1) = alice.encrypt::<S>(AD, b"legit-1").unwrap();
        let mut forged = c1.clone();
        forged[0] ^= 0xFF;
        assert!(bob.decrypt::<S, _>(&mut rng, &h1, &forged, AD).is_err());

        // 关键断言：伪造消息之后，原本合法的 m1 仍能正常解密（状态没被污染）
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h1, &c1, AD).unwrap(), b"legit-1");
    }

    #[test]
    fn wrong_ad_is_rejected() {
        let (mut alice, mut bob, mut rng) = established(13);
        let (h, ct) = alice.encrypt::<S>(AD, b"secret").unwrap();
        // 换会话 AD（跨会话移植密文）必须失败
        assert!(bob.decrypt::<S, _>(&mut rng, &h, &ct, b"conv:999").is_err());
        // 且状态未坏，正确 AD 仍可解
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), b"secret");
    }

    #[test]
    fn excessive_skip_is_refused() {
        let (mut alice, mut bob, mut rng) = established(14);
        // 先正常建立接收链
        let (h0, c0) = alice.encrypt::<S>(AD, b"m0").unwrap();
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h0, &c0, AD).unwrap(), b"m0");
        // 伪造同链但 n 远超上限的头 → DoS 护栏拒绝（在 AEAD 之前）
        let forged = Header {
            dh: h0.dh.clone(),
            pn: 0,
            n: MAX_SKIP + 5000,
        };
        let err = bob.decrypt::<S, _>(&mut rng, &forged, &c0, AD).err().unwrap();
        assert_eq!(err, CryptoError::DecryptRetryable);
    }
}

