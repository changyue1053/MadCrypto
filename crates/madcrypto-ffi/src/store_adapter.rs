//! C host storage bridge: only encrypted envelopes and metadata cross this ABI.
//! PlatformKeyStore remains injected on the Rust side; no raw key callback exists.
use madcrypto_core::persistence::{
    AtomicSessionStore, CommitOutcome, KeyRef, PersistenceError, Scope, SealedCommit,
};
use std::{ffi::c_void, marker::PhantomData, rc::Rc};

const LIMIT: usize = 2 * 1024 * 1024 + 2048;
const BLOB_LIMIT: usize = 1024 * 1024;
pub type LoadFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> i32;
pub type CommitFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    u32,
    u64,
    u64,
    *const u8,
    usize,
    *const u8,
    usize,
) -> i32;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StoreV1 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub ctx: *mut c_void,
    pub load: Option<LoadFn>,
    pub commit: Option<CommitFn>,
}
/// Single-thread-affine adapter. No Send/Sync and no ownership of host ctx.
pub struct CStoreAdapter {
    api: StoreV1,
    _thread_affine: PhantomData<Rc<()>>,
}
impl CStoreAdapter {
    /// # Safety
    /// Host ctx/function pointers must remain valid until adapter is dropped.
    /// Callbacks must obey madcrypto_store.h, including pointer bounds, no unwind,
    /// no reentrancy and atomic/authoritative storage semantics. Invalid host code
    /// can violate memory safety; this is not an untrusted-plugin sandbox.
    pub unsafe fn new(api: StoreV1) -> Result<Self, PersistenceError> {
        if api.struct_size < std::mem::size_of::<StoreV1>() as u32
            || api.abi_version != 1
            || api.load.is_none()
            || api.commit.is_none()
        {
            return Err(PersistenceError::Invalid);
        }
        Ok(Self {
            api,
            _thread_affine: PhantomData,
        })
    }
    fn read(
        &mut self,
        scope: &Scope,
        operation: &str,
    ) -> Result<Option<SealedCommit>, PersistenceError> {
        let key = scope_bytes(scope);
        let load = self.api.load.ok_or(PersistenceError::Invalid)?;
        let mut size = 0;
        let status = unsafe {
            load(
                self.api.ctx,
                key.as_ptr(),
                key.len(),
                operation.as_ptr(),
                operation.len(),
                std::ptr::null_mut(),
                0,
                &mut size,
            )
        };
        if status == 1 {
            return Ok(None);
        }
        if status != 0 {
            return Err(PersistenceError::StoreUnavailable);
        }
        if size == 0 || size > LIMIT {
            return Err(PersistenceError::Corrupt);
        }
        let mut bytes = vec![0; size];
        let mut actual = 0;
        let status = unsafe {
            load(
                self.api.ctx,
                key.as_ptr(),
                key.len(),
                operation.as_ptr(),
                operation.len(),
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut actual,
            )
        };
        // A vanished record between probe/read is not an authoritative absent read.
        if status != 0 {
            return Err(PersistenceError::StoreUnavailable);
        }
        if actual == 0 || actual > bytes.len() {
            return Err(PersistenceError::Corrupt);
        }
        bytes.truncate(actual);
        let record = decode(&bytes)?;
        if record.scope != *scope || (!operation.is_empty() && record.operation_id != operation) {
            return Err(PersistenceError::Corrupt);
        }
        Ok(Some(record))
    }
}
impl AtomicSessionStore for CStoreAdapter {
    fn load(&mut self, scope: &Scope) -> Result<Option<SealedCommit>, PersistenceError> {
        self.read(scope, "")
    }
    fn load_operation(
        &mut self,
        scope: &Scope,
        id: &str,
    ) -> Result<Option<SealedCommit>, PersistenceError> {
        if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
            return Err(PersistenceError::Invalid);
        }
        self.read(scope, id)
    }
    fn commit(&mut self, expected: Option<u64>, write: SealedCommit) -> CommitOutcome {
        if write.revision == 0
            || expected.and_then(|r| r.checked_add(1)).unwrap_or(1) != write.revision
            || expected == Some(u64::MAX)
        {
            return CommitOutcome::Rejected;
        }
        let Ok(envelope) = encode(&write) else {
            return CommitOutcome::Rejected;
        };
        let scope = scope_bytes(&write.scope);
        let Some(commit) = self.api.commit else {
            return CommitOutcome::Rejected;
        };
        let status = unsafe {
            commit(
                self.api.ctx,
                scope.as_ptr(),
                scope.len(),
                u32::from(expected.is_some()),
                expected.unwrap_or(0),
                write.revision,
                write.operation_id.as_ptr(),
                write.operation_id.len(),
                envelope.as_ptr(),
                envelope.len(),
            )
        };
        match status {
            0 => CommitOutcome::Committed,
            1 => CommitOutcome::Conflict,
            2 => CommitOutcome::Rejected,
            _ => CommitOutcome::Unknown,
        }
    }
}
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn scope_bytes(scope: &Scope) -> Vec<u8> {
    let mut key = Vec::new();
    let (a, b, c) = scope.components();
    for item in [a, b, c] {
        field(&mut key, item.as_bytes());
    }
    key
}
fn encode(r: &SealedCommit) -> Result<Vec<u8>, PersistenceError> {
    if r.format != 1
        || r.operation_id.is_empty()
        || r.operation_id.len() > 128
        || r.operation_id.chars().any(char::is_control)
        || r.state.len() > BLOB_LIMIT
        || r.effect.len() > BLOB_LIMIT
    {
        return Err(PersistenceError::Invalid);
    }
    let mut out = b"MCPS\x01".to_vec();
    out.extend_from_slice(&r.format.to_be_bytes());
    out.extend_from_slice(&r.revision.to_be_bytes());
    out.extend(scope_bytes(&r.scope));
    field(&mut out, r.key.alias().as_bytes());
    out.extend_from_slice(&r.key.version().to_be_bytes());
    field(&mut out, r.operation_id.as_bytes());
    field(&mut out, &r.state);
    field(&mut out, &r.effect);
    Ok(out)
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PersistenceError> {
        let end = self.pos.checked_add(n).ok_or(PersistenceError::Corrupt)?;
        let out = self
            .bytes
            .get(self.pos..end)
            .ok_or(PersistenceError::Corrupt)?;
        self.pos = end;
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32, PersistenceError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PersistenceError::Corrupt)?,
        ))
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8], PersistenceError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(PersistenceError::Corrupt);
        }
        self.take(n)
    }
    fn text(&mut self) -> Result<String, PersistenceError> {
        std::str::from_utf8(self.bytes(128)?)
            .map(str::to_owned)
            .map_err(|_| PersistenceError::Corrupt)
    }
}
fn decode(bytes: &[u8]) -> Result<SealedCommit, PersistenceError> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.take(5)? != b"MCPS\x01" {
        return Err(PersistenceError::Corrupt);
    }
    let format = c.u32()?;
    let revision = u64::from_be_bytes(
        c.take(8)?
            .try_into()
            .map_err(|_| PersistenceError::Corrupt)?,
    );
    let app = c.text()?;
    let account = c.text()?;
    let session = c.text()?;
    let scope = Scope::new(&app, &account, &session).map_err(|_| PersistenceError::Corrupt)?;
    let alias = c.text()?;
    let key = KeyRef::new(&alias, c.u32()?).map_err(|_| PersistenceError::Corrupt)?;
    let operation_id = c.text()?;
    let state = c.bytes(BLOB_LIMIT)?.to_vec();
    let effect = c.bytes(BLOB_LIMIT)?.to_vec();
    if c.pos != bytes.len()
        || format != 1
        || revision == 0
        || operation_id.is_empty()
        || operation_id.chars().any(char::is_control)
    {
        return Err(PersistenceError::Corrupt);
    }
    Ok(SealedCommit {
        format,
        scope,
        key,
        revision,
        operation_id,
        state,
        effect,
    })
}

#[cfg(all(test, feature = "c-test-fixtures"))]
mod tests {
    use super::*;
    use madcrypto_core::{
        keys::{DhPrivate, DhPublic, RootKey},
        persistence::{
            recover_effect, KeyError, KeyPolicy, KeyProtection, PersistentSession, PlatformKeyStore,
        },
        session::SecureSession,
    };
    use madcrypto_prims::{CipherSuite, IntlSuite as S};
    use zeroize::Zeroizing;
    unsafe extern "C" {
        fn madcrypto_store_fixture_new() -> *mut c_void;
        fn madcrypto_store_fixture_free(ctx: *mut c_void);
        fn madcrypto_store_fixture_mode(ctx: *mut c_void, mode: i32);
        fn madcrypto_store_fixture_api(ctx: *mut c_void, out: *mut StoreV1);
    }
    struct Fixture(*mut c_void);
    impl Fixture {
        fn new() -> Self {
            let p = unsafe { madcrypto_store_fixture_new() };
            assert!(!p.is_null());
            Self(p)
        }
        fn adapter(&mut self) -> CStoreAdapter {
            let mut api = StoreV1 {
                struct_size: 0,
                abi_version: 0,
                ctx: std::ptr::null_mut(),
                load: None,
                commit: None,
            };
            unsafe {
                madcrypto_store_fixture_api(self.0, &mut api);
                CStoreAdapter::new(api).unwrap()
            }
        }
        fn mode(&self, n: i32) {
            unsafe { madcrypto_store_fixture_mode(self.0, n) }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { madcrypto_store_fixture_free(self.0) }
        }
    }
    fn scope() -> Scope {
        Scope::new("app", "account", "session").unwrap()
    }
    fn record(revision: u64, id: &str) -> SealedCommit {
        SealedCommit {
            format: 1,
            scope: scope(),
            key: KeyRef::new("key", 1).unwrap(),
            revision,
            operation_id: id.into(),
            state: vec![7; 32],
            effect: vec![8; 32],
        }
    }
    #[test]
    fn real_c_callbacks_cas_read_and_operation_retention() {
        let mut f = Fixture::new();
        let mut store = f.adapter();
        assert!(store.load(&scope()).unwrap().is_none());
        assert_eq!(
            store.commit(None, record(1, "op-1")),
            CommitOutcome::Committed
        );
        assert_eq!(
            store.commit(None, record(1, "op-2")),
            CommitOutcome::Conflict
        );
        assert_eq!(
            store.commit(Some(1), record(2, "op-1")),
            CommitOutcome::Conflict
        );
        assert_eq!(
            store.commit(Some(1), record(2, "op-2")),
            CommitOutcome::Committed
        );
        assert_eq!(store.load(&scope()).unwrap().unwrap().revision, 2);
        assert_eq!(
            store
                .load_operation(&scope(), "op-1")
                .unwrap()
                .unwrap()
                .revision,
            1
        );
        assert!(store
            .load(&Scope::new("other", "account", "session").unwrap())
            .unwrap()
            .is_none());
    }
    #[test]
    fn io_and_malformed_callbacks_are_not_absence() {
        let mut f = Fixture::new();
        let mut store = f.adapter();
        store.commit(None, record(1, "op"));
        for mode in [1, 2, 6, 7, 8, 9, 10] {
            f.mode(mode);
            assert!(store.load(&scope()).is_err(), "mode {mode}");
        }
    }
    #[test]
    fn unknown_codes_and_revision_bounds_fail_closed() {
        let mut f = Fixture::new();
        let mut store = f.adapter();
        assert_eq!(
            store.commit(None, record(2, "bad")),
            CommitOutcome::Rejected
        );
        assert_eq!(
            store.commit(Some(u64::MAX), record(1, "bad")),
            CommitOutcome::Rejected
        );
        f.mode(5);
        assert_eq!(store.commit(None, record(1, "op")), CommitOutcome::Unknown);
        f.mode(0);
        assert_eq!(store.load(&scope()).unwrap().unwrap().revision, 1);
    }
    #[test]
    fn envelope_parser_bounds_and_trailing_bytes() {
        let encoded = encode(&record(1, "op")).unwrap();
        for end in 0..encoded.len() {
            assert!(decode(&encoded[..end]).is_err());
        }
        let mut extra = encoded.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        for i in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[i] ^= 0xff;
            let _ = decode(&mutated);
        }
        assert!(unsafe {
            CStoreAdapter::new(StoreV1 {
                struct_size: 0,
                abi_version: 1,
                ctx: std::ptr::null_mut(),
                load: None,
                commit: None,
            })
        }
        .is_err());
    }
    struct TestKeys(u64);
    impl PlatformKeyStore for TestKeys {
        fn create(
            &mut self,
            _: &Scope,
            _: &KeyRef,
            _: KeyPolicy,
        ) -> Result<KeyProtection, KeyError> {
            Err(KeyError::Unsupported)
        }
        fn delete(&mut self, _: &Scope, _: &KeyRef) -> Result<(), KeyError> {
            Err(KeyError::Unsupported)
        }
        fn seal(
            &mut self,
            _: &Scope,
            _: &KeyRef,
            aad: &[u8],
            pt: &[u8],
        ) -> Result<Vec<u8>, KeyError> {
            self.0 += 1;
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.0.to_be_bytes());
            let mut out = nonce.to_vec();
            out.extend(S::aead_seal(&[9; 32], &nonce, aad, pt));
            Ok(out)
        }
        fn open(
            &mut self,
            _: &Scope,
            _: &KeyRef,
            aad: &[u8],
            ct: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            if ct.len() < 12 {
                return Err(KeyError::Authentication);
            }
            S::aead_open(&[9; 32], ct[..12].try_into().unwrap(), aad, &ct[12..])
                .map(Zeroizing::new)
                .map_err(|_| KeyError::Authentication)
        }
    }
    fn persistent() -> PersistentSession {
        let sk = vec![3; 32];
        let pk = S::dh_public(&sk).unwrap();
        PersistentSession::new(
            scope(),
            KeyRef::new("key", 1).unwrap(),
            SecureSession::receiver(RootKey::new([4; 32]), DhPrivate::new(sk), DhPublic::new(pk)),
        )
    }
    #[test]
    fn coordinator_unknown_and_reload_over_real_c_store() {
        let mut f = Fixture::new();
        let mut store = f.adapter();
        let mut keys = TestKeys(0);
        let mut session = persistent();
        f.mode(4);
        assert_eq!(
            session
                .update(&mut store, &mut keys, "op", |_| Ok(
                    b"must-not-cross-C".to_vec()
                ))
                .unwrap_err(),
            PersistenceError::RecoveryRequired
        );
        assert!(session.recovery_required());
        f.mode(0);
        let row = store.load(&scope()).unwrap().unwrap();
        let envelope = encode(&row).unwrap();
        assert!(!envelope.windows(16).any(|w| w == b"must-not-cross-C"));
        assert_eq!(
            &**recover_effect(&mut store, &mut keys, &scope(), "op")
                .unwrap()
                .unwrap(),
            b"must-not-cross-C"
        );
        assert_eq!(
            PersistentSession::load(&mut store, &mut keys, scope())
                .unwrap()
                .unwrap()
                .revision(),
            Some(1)
        );
    }
    #[test]
    fn coordinator_unknown_without_c_write_has_no_recoverable_effect() {
        let mut f = Fixture::new();
        let mut store = f.adapter();
        let mut keys = TestKeys(0);
        let mut session = persistent();
        f.mode(3);
        assert_eq!(
            session
                .update(&mut store, &mut keys, "op", |_| Ok(vec![]))
                .unwrap_err(),
            PersistenceError::RecoveryRequired
        );
        f.mode(0);
        assert!(store.load(&scope()).unwrap().is_none());
        assert!(recover_effect(&mut store, &mut keys, &scope(), "op")
            .unwrap()
            .is_none());
    }
    #[test]
    fn coordinator_definite_c_rejection_can_retry_same_state() {
        let mut f = Fixture::new();
        let mut store = f.adapter();
        let mut keys = TestKeys(0);
        let mut session = persistent();
        f.mode(11);
        assert_eq!(
            session
                .update(&mut store, &mut keys, "op", |_| Ok(b"effect".to_vec()))
                .unwrap_err(),
            PersistenceError::Rejected
        );
        assert_eq!(session.revision(), None);
        assert!(!session.recovery_required());
        f.mode(0);
        assert!(store.load(&scope()).unwrap().is_none());
        assert_eq!(
            &**session
                .update(&mut store, &mut keys, "op", |_| Ok(b"effect".to_vec()))
                .unwrap(),
            b"effect"
        );
        assert_eq!(session.revision(), Some(1));
    }
}
