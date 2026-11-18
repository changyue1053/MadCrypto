//! 线格式编解码（架构 §6/§7 帧图的代码化；FFI 与传输层的字节面，实施 P8 前置）。
//!
//! 纪律：解码是**系统边界**（不可信字节），所有读取经带界游标，任何截断/越界/非法
//! 枚举值都走 `Malformed` 错误返回——`decode(任意字节) 永不 panic` 是 fuzz 目标（§17 L4）。
//! 版本字节先行：未来格式演进走版本协商，旧端对新版本报 Malformed 而非错解。

use madcrypto_prims::SuiteId;

use crate::error::{CryptoError, Result};
use crate::keys::{DhPublic, IdentityPublic, SignPublic};
use crate::ratchet::Header;
use crate::x3dh::InitialMessage;

const WIRE_V1: u8 = 1;
/// 单字段长度上限（公钥/密文的合理上界，防长度字段诈骗导致的巨额分配）。
const MAX_FIELD: usize = 64 * 1024;

// ---- 带界游标：所有解码的唯一读取入口（会话序列化 §15 复用同一套「永不 panic」机制）----

pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(CryptoError::Malformed)?;
        if end > self.buf.len() {
            return Err(CryptoError::Malformed);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("定长切片")))
    }
    pub(crate) fn arr32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("定长切片"))
    }
    pub(crate) fn lv16(&mut self) -> Result<&'a [u8]> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().expect("定长切片")) as usize;
        self.take(n)
    }
    pub(crate) fn lv32(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > MAX_FIELD {
            return Err(CryptoError::Malformed);
        }
        self.take(n)
    }
    pub(crate) fn finish(self) -> Result<()> {
        // 尾随垃圾字节 = 非法（防在合法报文后夹带）
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CryptoError::Malformed)
        }
    }
}

pub(crate) fn put16(out: &mut Vec<u8>, field: &[u8]) {
    debug_assert!(field.len() <= u16::MAX as usize);
    out.extend_from_slice(&(field.len() as u16).to_be_bytes());
    out.extend_from_slice(field);
}

pub(crate) fn put32(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

// ---- 常规棘轮消息 ----

/// `[ver][suite][pn:4][n:4][dh:lv16][ct:lv32]`
pub fn encode_message(suite: SuiteId, header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + header.dh.as_slice().len() + ciphertext.len());
    out.push(WIRE_V1);
    out.push(suite.as_u8());
    out.extend_from_slice(&header.pn.to_be_bytes());
    out.extend_from_slice(&header.n.to_be_bytes());
    put16(&mut out, header.dh.as_slice());
    put32(&mut out, ciphertext);
    out
}

pub fn decode_message(bytes: &[u8]) -> Result<(SuiteId, Header, Vec<u8>)> {
    let mut c = Cursor::new(bytes);
    if c.u8()? != WIRE_V1 {
        return Err(CryptoError::Malformed);
    }
    let suite = SuiteId::from_u8(c.u8()?).ok_or(CryptoError::Malformed)?;
    let pn = c.u32()?;
    let n = c.u32()?;
    let dh = DhPublic::new(c.lv16()?.to_vec());
    let ct = c.lv32()?.to_vec();
    c.finish()?;
    Ok((suite, Header { dh, pn, n }, ct))
}

// ---- PreKey Bundle（注册期发布到目录的公钥包）----

use crate::x3dh::PreKeyBundle;

/// `[ver][suite][ik_dh:lv16][ik_sign:lv16][spk:lv16][spk_sig:lv16][opk_flag][opk_id:4?][opk:lv16?]`
pub fn encode_bundle(b: &PreKeyBundle) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.push(WIRE_V1);
    out.push(b.suite.as_u8());
    put16(&mut out, b.identity.dh.as_slice());
    put16(&mut out, b.identity.sign.as_slice());
    put16(&mut out, b.signed_prekey.as_slice());
    put16(&mut out, &b.signed_prekey_sig);
    match &b.one_time_prekey {
        Some((id, pk)) => {
            out.push(1);
            out.extend_from_slice(&id.to_be_bytes());
            put16(&mut out, pk.as_slice());
        }
        None => out.push(0),
    }
    out
}

pub fn decode_bundle(bytes: &[u8]) -> Result<PreKeyBundle> {
    let mut c = Cursor::new(bytes);
    if c.u8()? != WIRE_V1 {
        return Err(CryptoError::Malformed);
    }
    let suite = SuiteId::from_u8(c.u8()?).ok_or(CryptoError::Malformed)?;
    let ik_dh = DhPublic::new(c.lv16()?.to_vec());
    let ik_sign = SignPublic::new(c.lv16()?.to_vec());
    let signed_prekey = DhPublic::new(c.lv16()?.to_vec());
    let signed_prekey_sig = c.lv16()?.to_vec();
    let one_time_prekey = match c.u8()? {
        0 => None,
        1 => {
            let id = c.u32()?;
            Some((id, DhPublic::new(c.lv16()?.to_vec())))
        }
        _ => return Err(CryptoError::Malformed),
    };
    c.finish()?;
    Ok(PreKeyBundle {
        suite,
        identity: IdentityPublic { dh: ik_dh, sign: ik_sign },
        signed_prekey,
        signed_prekey_sig,
        one_time_prekey,
    })
}

// ---- PreKeyMessage（首包：握手头 + 首条棘轮消息）----

/// `[ver][suite][ik_dh:lv16][ik_sign:lv16][ek:lv16][opk_flag][opk_id:4?][inner:lv32]`
pub fn encode_prekey_message(im: &InitialMessage, inner_message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + inner_message.len());
    out.push(WIRE_V1);
    out.push(im.suite.as_u8());
    put16(&mut out, im.identity.dh.as_slice());
    put16(&mut out, im.identity.sign.as_slice());
    put16(&mut out, im.ephemeral.as_slice());
    match im.one_time_prekey_id {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id.to_be_bytes());
        }
        None => out.push(0),
    }
    put32(&mut out, inner_message);
    out
}

pub fn decode_prekey_message(bytes: &[u8]) -> Result<(InitialMessage, Vec<u8>)> {
    let mut c = Cursor::new(bytes);
    if c.u8()? != WIRE_V1 {
        return Err(CryptoError::Malformed);
    }
    let suite = SuiteId::from_u8(c.u8()?).ok_or(CryptoError::Malformed)?;
    let ik_dh = DhPublic::new(c.lv16()?.to_vec());
    let ik_sign = SignPublic::new(c.lv16()?.to_vec());
    let ephemeral = DhPublic::new(c.lv16()?.to_vec());
    let one_time_prekey_id = match c.u8()? {
        0 => None,
        1 => Some(c.u32()?),
        _ => return Err(CryptoError::Malformed),
    };
    let inner = c.lv32()?.to_vec();
    c.finish()?;
    Ok((
        InitialMessage {
            suite,
            identity: IdentityPublic { dh: ik_dh, sign: ik_sign },
            ephemeral,
            one_time_prekey_id,
        },
        inner,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::generate_identity;
    use madcrypto_prims::{CipherSuite, IntlSuite};
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;

    fn sample_message() -> Vec<u8> {
        let header = Header {
            dh: DhPublic::new(vec![7u8; 32]),
            pn: 3,
            n: 42,
        };
        encode_message(SuiteId::Intl, &header, b"ciphertext-bytes")
    }

    #[test]
    fn message_roundtrip() {
        let bytes = sample_message();
        let (suite, h, ct) = decode_message(&bytes).unwrap();
        assert_eq!(suite, SuiteId::Intl);
        assert_eq!((h.pn, h.n), (3, 42));
        assert_eq!(h.dh.as_slice(), &[7u8; 32]);
        assert_eq!(ct, b"ciphertext-bytes");
    }

    #[test]
    fn prekey_message_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(80);
        let id = generate_identity::<S, _>(&mut rng);
        let ek = S::dh_keypair(&mut rng);
        let im = InitialMessage {
            suite: SuiteId::Intl,
            identity: id.public(),
            ephemeral: DhPublic::new(ek.public),
            one_time_prekey_id: Some(7),
        };
        let bytes = encode_prekey_message(&im, b"inner-ratchet-msg");
        let (decoded, inner) = decode_prekey_message(&bytes).unwrap();
        assert_eq!(decoded.identity, im.identity);
        assert_eq!(decoded.ephemeral, im.ephemeral);
        assert_eq!(decoded.one_time_prekey_id, Some(7));
        assert_eq!(inner, b"inner-ratchet-msg");
    }

    /// 每个截断点都必须干净地报 Malformed——解码器没有任何"读一半"的成功路径。
    #[test]
    fn every_truncation_is_malformed() {
        let bytes = sample_message();
        for cut in 0..bytes.len() {
            assert_eq!(
                decode_message(&bytes[..cut]).err().unwrap(),
                CryptoError::Malformed,
                "截断到 {cut} 字节必须报 Malformed"
            );
        }
        // 尾随垃圾同样非法
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_message(&trailing).err().unwrap(), CryptoError::Malformed);
    }

    #[test]
    fn bundle_roundtrip_and_truncation() {
        let mut rng = ChaCha20Rng::seed_from_u64(82);
        let id = generate_identity::<S, _>(&mut rng);
        let (_sp, spk_pub, spk_sig) = crate::x3dh::new_signed_prekey::<S, _>(&mut rng, &id).unwrap();
        let (_op, opk_pub) = crate::x3dh::new_one_time_prekey::<S, _>(&mut rng);
        let bundle = PreKeyBundle {
            suite: SuiteId::Intl,
            identity: id.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: Some((7, opk_pub)),
        };
        let bytes = encode_bundle(&bundle);
        let decoded = decode_bundle(&bytes).unwrap();
        assert_eq!(decoded.identity, bundle.identity);
        assert_eq!(decoded.signed_prekey, bundle.signed_prekey);
        assert_eq!(decoded.one_time_prekey, bundle.one_time_prekey);
        for cut in 0..bytes.len() {
            assert!(decode_bundle(&bytes[..cut]).is_err(), "截断 {cut} 必须报错");
        }
    }

    /// fuzz-lite（§17 L4 雏形）：随机字节与逐字节变异——解码永不 panic。
    #[test]
    fn fuzz_lite_decode_never_panics() {
        let mut rng = ChaCha20Rng::seed_from_u64(81);

        // ① 1 万条随机字节串
        for _ in 0..10_000 {
            let len = (rng.next_u32() % 256) as usize;
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            let _ = decode_message(&buf); // Err 即可，绝不 panic
            let _ = decode_prekey_message(&buf);
            let _ = decode_bundle(&buf);
        }

        // ② 合法报文逐字节变异（每位翻转一次）
        let good = sample_message();
        for i in 0..good.len() {
            let mut mutated = good.clone();
            mutated[i] ^= 0xFF;
            let _ = decode_message(&mutated); // 解出或报错都行，不 panic 且不越界
        }

        // ③ 长度字段诈骗：声称 4GB 密文 → Malformed 而非巨额分配
        let mut bomb = Vec::new();
        bomb.push(1); // ver
        bomb.push(1); // suite
        bomb.extend_from_slice(&0u32.to_be_bytes()); // pn
        bomb.extend_from_slice(&0u32.to_be_bytes()); // n
        bomb.extend_from_slice(&(32u16).to_be_bytes());
        bomb.extend_from_slice(&[0u8; 32]);
        bomb.extend_from_slice(&u32::MAX.to_be_bytes()); // ct_len = 4GB
        assert_eq!(decode_message(&bomb).err().unwrap(), CryptoError::Malformed);
    }
}

