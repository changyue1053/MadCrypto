//! PQXDH 形态的异步握手（架构 §6）。
//!
//! 「离线建密」：Bob 预先把 prekey bundle 放到（不可信的）目录，Alice 拉取后本地
//! 完成 3~4 次 DH（+ 预留 KEM 汇合点）算出共享密钥 SK，Bob 上线后补算同一个 SK。
//! 服务器全程只见公钥与密文。v1.0 以 PQ 路缺席的退化态（= X3DH）交付，
//! KDF 汇合点 `kdf_x3dh` 已能吃多路输入，打开 KEM 即 PQXDH（架构 §19，零重构）。

use madcrypto_prims::{CipherSuite, SuiteId};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::kdf::kdf_x3dh;
use crate::keys::{DhPrivate, DhPublic, IdentityKeyPair, IdentityPublic, RootKey, SignPrivate, SignPublic};

/// 注册期：生成长期身份密钥对（DH 部分 + 签名部分）。
pub fn generate_identity<S: CipherSuite, R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
) -> IdentityKeyPair {
    let dh = S::dh_keypair(rng);
    let sg = S::sign_keypair(rng);
    IdentityKeyPair {
        dh_private: DhPrivate::new(dh.private),
        dh_public: DhPublic::new(dh.public),
        sign_private: SignPrivate::new(sg.private),
        sign_public: SignPublic::new(sg.public),
    }
}

/// 注册期：生成一把已签名预共享密钥（SPK），由身份签名密钥背书（防调包，架构 §6）。
pub fn new_signed_prekey<S: CipherSuite, R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    identity: &IdentityKeyPair,
) -> Result<(DhPrivate, DhPublic, Vec<u8>)> {
    let kp = S::dh_keypair(rng);
    let sig = S::sign(identity.sign_private.expose(), &kp.public)?;
    Ok((DhPrivate::new(kp.private), DhPublic::new(kp.public), sig))
}

/// 注册期：生成一把一次性预共享密钥（OPK）。用一把销一把（架构 §6）。
pub fn new_one_time_prekey<S: CipherSuite, R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
) -> (DhPrivate, DhPublic) {
    let kp = S::dh_keypair(rng);
    (DhPrivate::new(kp.private), DhPublic::new(kp.public))
}

/// Bob 发布到目录的 prekey bundle（不可信目录只搬运公钥）。
#[derive(Clone)]
pub struct PreKeyBundle {
    pub suite: SuiteId,
    pub identity: IdentityPublic,
    pub signed_prekey: DhPublic,
    pub signed_prekey_sig: Vec<u8>,
    /// (opk_id, opk_public)；目录原子消耗，可能缺席（架构 §6 降级路径）。
    pub one_time_prekey: Option<(u32, DhPublic)>,
    // pqpk: Option<KemPublic> —— PQXDH 预留字段，v1.0 缺席
}

/// Alice 首包头（PreKeyMessage 前缀，随第一条密文发出）。
#[derive(Clone)]
pub struct InitialMessage {
    pub suite: SuiteId,
    pub identity: IdentityPublic,
    pub ephemeral: DhPublic,
    pub one_time_prekey_id: Option<u32>,
    // kyber_ct: Option<Vec<u8>> —— PQXDH 预留，v1.0 缺席
}

/// 发起方握手产物：初始 root、对端初始棘轮公钥（= SPK_B）、要发出的首包头。
pub struct InitiatorResult {
    pub root: RootKey,
    pub their_ratchet_public: DhPublic,
    pub initial_message: InitialMessage,
}

/// Alice：拉到 Bob 的 bundle → 本地算 SK（Bob 无需在线）。
pub fn initiate<S: CipherSuite, R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    my_identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<InitiatorResult> {
    if bundle.suite != S::id() {
        return Err(CryptoError::SuiteMismatch);
    }
    // SPK 必须由对端身份签名背书，否则就是目录发的假钥（MITM）
    if !S::verify(
        bundle.identity.sign.as_slice(),
        bundle.signed_prekey.as_slice(),
        &bundle.signed_prekey_sig,
    ) {
        return Err(CryptoError::Handshake("SPK 签名非法"));
    }

    let ek = S::dh_keypair(rng);
    let ek_priv = DhPrivate::new(ek.private);

    // DH1=IK_A·SPK_B  DH2=EK_A·IK_B  DH3=EK_A·SPK_B  DH4=EK_A·OPK_B(可选)
    let dh1 = S::dh(my_identity.dh_private.expose(), bundle.signed_prekey.as_slice())?;
    let dh2 = S::dh(ek_priv.expose(), bundle.identity.dh.as_slice())?;
    let dh3 = S::dh(ek_priv.expose(), bundle.signed_prekey.as_slice())?;

    let mut concat = Vec::with_capacity(128);
    concat.extend_from_slice(&dh1);
    concat.extend_from_slice(&dh2);
    concat.extend_from_slice(&dh3);

    let mut opk_id = None;
    if let Some((id, opk_pub)) = &bundle.one_time_prekey {
        let dh4 = S::dh(ek_priv.expose(), opk_pub.as_slice())?;
        concat.extend_from_slice(&dh4);
        opk_id = Some(*id);
    }

    let root = kdf_x3dh::<S>(&concat);
    concat.zeroize();

    Ok(InitiatorResult {
        root,
        their_ratchet_public: bundle.signed_prekey.clone(),
        initial_message: InitialMessage {
            suite: S::id(),
            identity: my_identity.public(),
            ephemeral: DhPublic::new(ek.public),
            one_time_prekey_id: opk_id,
        },
    })
}

/// Bob 侧握手所需的私钥集合（从本地 prekey 库存查出，OPK 按 id 取出即删）。
pub struct ResponderKeys<'a> {
    pub identity: &'a IdentityKeyPair,
    pub signed_prekey_private: &'a DhPrivate,
    /// 与 `InitialMessage.one_time_prekey_id` 对应；id 存在但私钥缺失 = OPK 已被消费。
    pub one_time_prekey_private: Option<&'a DhPrivate>,
}

/// Bob 握手产物：同一个 root，以及自己的初始棘轮密钥对（= SPK_B）。
pub struct ResponderResult {
    pub root: RootKey,
    pub my_ratchet_private: DhPrivate,
    pub my_ratchet_public: DhPublic,
}

/// Bob：收到 Alice 首包 → 用自己的私钥补算同一个 SK。
pub fn respond<S: CipherSuite>(
    keys: ResponderKeys<'_>,
    msg: &InitialMessage,
) -> Result<ResponderResult> {
    if msg.suite != S::id() {
        return Err(CryptoError::SuiteMismatch);
    }
    let spk_priv = keys.signed_prekey_private;

    let dh1 = S::dh(spk_priv.expose(), msg.identity.dh.as_slice())?;
    let dh2 = S::dh(keys.identity.dh_private.expose(), msg.ephemeral.as_slice())?;
    let dh3 = S::dh(spk_priv.expose(), msg.ephemeral.as_slice())?;

    let mut concat = Vec::with_capacity(128);
    concat.extend_from_slice(&dh1);
    concat.extend_from_slice(&dh2);
    concat.extend_from_slice(&dh3);

    // OPK 一致性：Alice 声明用了 OPK，Bob 必须能取出对应私钥，否则握手失败
    if msg.one_time_prekey_id.is_some() {
        let opk = keys
            .one_time_prekey_private
            .ok_or(CryptoError::Handshake("OPK 已被消费或丢失"))?;
        let dh4 = S::dh(opk.expose(), msg.ephemeral.as_slice())?;
        concat.extend_from_slice(&dh4);
    }

    let root = kdf_x3dh::<S>(&concat);
    concat.zeroize();

    let spk_pub = DhPublic::new(S::dh_public(spk_priv.expose())?);
    Ok(ResponderResult {
        root,
        my_ratchet_private: DhPrivate::new(spk_priv.expose().to_vec()),
        my_ratchet_public: spk_pub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use subtle::ConstantTimeEq;

    type S = IntlSuite;

    /// 构造一个完整的 Bob（身份 + SPK + 一把 OPK），返回 bundle 与私钥。
    fn setup_bob(
        rng: &mut ChaCha20Rng,
        with_opk: bool,
    ) -> (IdentityKeyPair, DhPrivate, Option<DhPrivate>, PreKeyBundle) {
        let id = generate_identity::<S, _>(rng);
        let (spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(rng, &id).unwrap();
        let (opk_priv, opk_entry) = if with_opk {
            let (p, pubk) = new_one_time_prekey::<S, _>(rng);
            (Some(p), Some((7u32, pubk)))
        } else {
            (None, None)
        };
        let bundle = PreKeyBundle {
            suite: S::id(),
            identity: id.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: opk_entry,
        };
        (id, spk_priv, opk_priv, bundle)
    }

    #[test]
    fn initiator_and_responder_derive_same_root_with_opk() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = generate_identity::<S, _>(&mut rng);
        let (bob, spk_priv, opk_priv, bundle) = setup_bob(&mut rng, true);

        let init = initiate::<S, _>(&mut rng, &alice, &bundle).unwrap();
        let resp = respond::<S>(
            ResponderKeys {
                identity: &bob,
                signed_prekey_private: &spk_priv,
                one_time_prekey_private: opk_priv.as_ref(),
            },
            &init.initial_message,
        )
        .unwrap();

        assert!(
            bool::from(init.root.ct_eq(&resp.root)),
            "Alice 与 Bob 必须算出同一个初始 root key"
        );
    }

    #[test]
    fn handshake_works_without_opk() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let alice = generate_identity::<S, _>(&mut rng);
        let (bob, spk_priv, _none, bundle) = setup_bob(&mut rng, false);
        let init = initiate::<S, _>(&mut rng, &alice, &bundle).unwrap();
        let resp = respond::<S>(
            ResponderKeys {
                identity: &bob,
                signed_prekey_private: &spk_priv,
                one_time_prekey_private: None,
            },
            &init.initial_message,
        )
        .unwrap();
        assert!(bool::from(init.root.ct_eq(&resp.root)));
    }

    #[test]
    fn tampered_spk_signature_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let alice = generate_identity::<S, _>(&mut rng);
        let (_bob, _spk, _opk, mut bundle) = setup_bob(&mut rng, true);
        bundle.signed_prekey_sig[0] ^= 1; // 目录发假钥 / 篡改签名
        let err = initiate::<S, _>(&mut rng, &alice, &bundle).err().unwrap();
        assert_eq!(err, CryptoError::Handshake("SPK 签名非法"));
    }

    #[test]
    fn suite_mismatch_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let alice = generate_identity::<S, _>(&mut rng);
        let (_bob, _spk, _opk, mut bundle) = setup_bob(&mut rng, true);
        bundle.suite = SuiteId::Sm; // 降级/错配套件声明
        let err = initiate::<S, _>(&mut rng, &alice, &bundle).err().unwrap();
        assert_eq!(err, CryptoError::SuiteMismatch);
    }

    #[test]
    fn responder_missing_consumed_opk_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let alice = generate_identity::<S, _>(&mut rng);
        let (bob, spk_priv, _opk, bundle) = setup_bob(&mut rng, true);
        let init = initiate::<S, _>(&mut rng, &alice, &bundle).unwrap();
        // Alice 用了 OPK，但 Bob 侧该 OPK 已被消费（None）→ 握手失败
        let err = respond::<S>(
            ResponderKeys {
                identity: &bob,
                signed_prekey_private: &spk_priv,
                one_time_prekey_private: None,
            },
            &init.initial_message,
        )
        .err().unwrap();
        assert_eq!(err, CryptoError::Handshake("OPK 已被消费或丢失"));
    }
}

