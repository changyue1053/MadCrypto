//! Host-injected encrypted session persistence. No platform key or database runtime
//! is linked. A successful commit seals both candidate state and opaque effect;
//! ambiguous outcomes freeze the local session until authoritative reload.
use crate::session::SecureSession;
use zeroize::Zeroizing;

const MAX_COMPONENT: usize = 128;
const MAX_BLOB: usize = 1024 * 1024;
const FORMAT: u32 = 1;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Scope {
    app: String,
    account: String,
    session: String,
}
impl Scope {
    pub fn new(app: &str, account: &str, session: &str) -> Result<Self, PersistenceError> {
        for part in [app, account, session] {
            validate(part)?;
        }
        Ok(Self {
            app: app.into(),
            account: account.into(),
            session: session.into(),
        })
    }
    pub fn components(&self) -> (&str, &str, &str) {
        (&self.app, &self.account, &self.session)
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct KeyRef {
    alias: String,
    version: u32,
}
impl KeyRef {
    pub fn new(alias: &str, version: u32) -> Result<Self, PersistenceError> {
        validate(alias)?;
        if version == 0 {
            return Err(PersistenceError::Invalid);
        }
        Ok(Self {
            alias: alias.into(),
            version,
        })
    }
    pub fn alias(&self) -> &str {
        &self.alias
    }
    pub fn version(&self) -> u32 {
        self.version
    }
}
fn validate(s: &str) -> Result<(), PersistenceError> {
    if s.is_empty() || s.len() > MAX_COMPONENT || s.chars().any(char::is_control) {
        Err(PersistenceError::Invalid)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Locked,
    NotFound,
    Denied,
    Unsupported,
    Authentication,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    Software,
    OsProtected,
    HardwareBacked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPolicy {
    pub minimum: KeyProtection,
    pub user_presence: bool,
}

/// Platform implementation owns wrapping keys, nonce uniqueness and access-control checks.
/// These protect snapshots at rest; protocol private keys still load into Rust memory.
/// seal must use authenticated encryption with unique nonces across process
/// restarts, concurrent writers and failed seal attempts under the same key.
/// Changing AAD does NOT permit nonce reuse. open verifies AAD
/// before returning plaintext. Returned ciphertext includes its nonce/algorithm
/// framing. Missing/locked keys never fall back to plaintext or generate new keys.
/// create must fail if the requested policy cannot be enforced. delete must only
/// affect the exact scope+alias+version. No platform implementation is bundled.
pub trait PlatformKeyStore {
    fn create(
        &mut self,
        scope: &Scope,
        key: &KeyRef,
        policy: KeyPolicy,
    ) -> Result<KeyProtection, KeyError>;
    fn delete(&mut self, scope: &Scope, key: &KeyRef) -> Result<(), KeyError>;
    fn seal(
        &mut self,
        scope: &Scope,
        key: &KeyRef,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyError>;
    fn open(
        &mut self,
        scope: &Scope,
        key: &KeyRef,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceError {
    Invalid,
    Key(KeyError),
    StoreUnavailable,
    Conflict,
    Rejected,
    RecoveryRequired,
    Corrupt,
    Protocol,
}

/// Envelope metadata is authenticated as AAD, not trusted until open succeeds.
/// Scope/alias are metadata and may identify an account: storage and logs need
/// host privacy controls even though state/effect are encrypted.
#[derive(Clone)]
pub struct SealedCommit {
    pub format: u32,
    pub scope: Scope,
    pub key: KeyRef,
    pub revision: u64,
    pub operation_id: String,
    pub state: Vec<u8>,
    pub effect: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed,
    /// No write; expected revision mismatched or operation id already exists.
    Conflict,
    /// Definitive no-write failure (e.g. quota).
    Rejected,
    /// May have committed. No more work until authoritative recovery/reload.
    Unknown,
}
/// Transaction must atomically CAS the per-scope revision AND insert a unique
/// per-scope operation id with both sealed blobs. None means insert only.
/// Reads must distinguish missing from IO failure. After Unknown, load must use
/// recovered authoritative state (not a lagging replica). CAS protects concurrent
/// writers, not hostile disk rollback; rollback prevention needs a trusted anchor.
pub trait AtomicSessionStore {
    fn load(&mut self, scope: &Scope) -> Result<Option<SealedCommit>, PersistenceError>;
    fn commit(&mut self, expected: Option<u64>, write: SealedCommit) -> CommitOutcome;
    /// Retain operation records until the host has acknowledged/durably consumed them.
    fn load_operation(
        &mut self,
        scope: &Scope,
        operation_id: &str,
    ) -> Result<Option<SealedCommit>, PersistenceError>;
}

fn aad(scope: &Scope, key: &KeyRef, revision: u64, operation: &str, kind: u8) -> Vec<u8> {
    let mut out = b"MadCrypto/persistence/v1".to_vec();
    out.extend_from_slice(&FORMAT.to_be_bytes());
    out.push(kind);
    for item in [
        scope.app.as_str(),
        scope.account.as_str(),
        scope.session.as_str(),
        key.alias.as_str(),
        operation,
    ] {
        out.extend_from_slice(&(item.len() as u32).to_be_bytes());
        out.extend_from_slice(item.as_bytes());
    }
    out.extend_from_slice(&key.version.to_be_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out
}

pub struct PersistentSession {
    scope: Scope,
    key: KeyRef,
    revision: Option<u64>,
    state: SecureSession,
    recovery_required: bool,
}
impl PersistentSession {
    /// Uncommitted session; host must supply an already-provisioned key.
    /// First commit is insert-only. There is no implicit identity/key creation.
    pub fn new(scope: Scope, key: KeyRef, state: SecureSession) -> Self {
        Self {
            scope,
            key,
            revision: None,
            state,
            recovery_required: false,
        }
    }
    pub fn revision(&self) -> Option<u64> {
        self.revision
    }
    pub fn recovery_required(&self) -> bool {
        self.recovery_required
    }
    pub fn load<S: AtomicSessionStore, K: PlatformKeyStore>(
        store: &mut S,
        keys: &mut K,
        scope: Scope,
    ) -> Result<Option<Self>, PersistenceError> {
        let Some(record) = store.load(&scope)? else {
            return Ok(None);
        };
        if record.format != FORMAT
            || record.scope != scope
            || record.revision == 0
            || record.state.len() > MAX_BLOB
            || record.effect.len() > MAX_BLOB
            || validate(&record.operation_id).is_err()
        {
            return Err(PersistenceError::Corrupt);
        }
        let clear = keys
            .open(
                &scope,
                &record.key,
                &aad(
                    &scope,
                    &record.key,
                    record.revision,
                    &record.operation_id,
                    0,
                ),
                &record.state,
            )
            .map_err(PersistenceError::Key)?;
        if clear.len() > MAX_BLOB {
            return Err(PersistenceError::Corrupt);
        }
        let state = SecureSession::deserialize(&clear).map_err(|_| PersistenceError::Corrupt)?;
        Ok(Some(Self {
            scope,
            key: record.key,
            revision: Some(record.revision),
            state,
            recovery_required: false,
        }))
    }
    /// Apply protocol-only work to a candidate. Closure MUST NOT perform network
    /// IO or externally publish the candidate output. Return bytes (ciphertext or
    /// plaintext) are released only after an atomic encrypted commit succeeds.
    /// No automatic retry: callers reconcile operation IDs after Unknown/Conflict.
    pub fn update<S, K, F>(
        &mut self,
        store: &mut S,
        keys: &mut K,
        operation_id: &str,
        work: F,
    ) -> Result<Zeroizing<Vec<u8>>, PersistenceError>
    where
        S: AtomicSessionStore,
        K: PlatformKeyStore,
        F: FnOnce(&mut SecureSession) -> Result<Vec<u8>, crate::CryptoError>,
    {
        if self.recovery_required {
            return Err(PersistenceError::RecoveryRequired);
        }
        validate(operation_id)?;
        let revision = self
            .revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(PersistenceError::Invalid)?;
        let mut candidate = self.state.snapshot();
        let effect = Zeroizing::new(work(&mut candidate).map_err(|_| PersistenceError::Protocol)?);
        let snapshot = Zeroizing::new(candidate.serialize());
        if snapshot.len() > MAX_BLOB || effect.len() > MAX_BLOB {
            return Err(PersistenceError::Invalid);
        }
        let sealed_state = keys
            .seal(
                &self.scope,
                &self.key,
                &aad(&self.scope, &self.key, revision, operation_id, 0),
                &snapshot,
            )
            .map_err(PersistenceError::Key)?;
        let sealed_effect = keys
            .seal(
                &self.scope,
                &self.key,
                &aad(&self.scope, &self.key, revision, operation_id, 1),
                &effect,
            )
            .map_err(PersistenceError::Key)?;
        if sealed_state.len() > MAX_BLOB || sealed_effect.len() > MAX_BLOB {
            return Err(PersistenceError::Invalid);
        }
        let write = SealedCommit {
            format: FORMAT,
            scope: self.scope.clone(),
            key: self.key.clone(),
            revision,
            operation_id: operation_id.into(),
            state: sealed_state,
            effect: sealed_effect,
        };
        // Host commit may panic after a durable write. Freeze before crossing
        // that boundary; a caller catching unwind must not reuse stale state.
        self.recovery_required = true;
        match store.commit(self.revision, write) {
            CommitOutcome::Committed => {
                self.recovery_required = false;
                self.state = candidate;
                self.revision = Some(revision);
                Ok(effect)
            }
            CommitOutcome::Rejected => {
                self.recovery_required = false;
                Err(PersistenceError::Rejected)
            }
            CommitOutcome::Conflict => {
                self.recovery_required = true;
                Err(PersistenceError::Conflict)
            }
            CommitOutcome::Unknown => {
                self.recovery_required = true;
                Err(PersistenceError::RecoveryRequired)
            }
        }
    }
}

/// Reconcile a possibly committed operation before retrying any external effect.
/// Returned bytes are still not evidence the external effect was delivered.
pub fn recover_effect<S: AtomicSessionStore, K: PlatformKeyStore>(
    store: &mut S,
    keys: &mut K,
    scope: &Scope,
    operation_id: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, PersistenceError> {
    validate(operation_id)?;
    let Some(record) = store.load_operation(scope, operation_id)? else {
        return Ok(None);
    };
    if record.format != FORMAT
        || record.scope != *scope
        || record.operation_id != operation_id
        || record.revision == 0
        || record.effect.len() > MAX_BLOB
    {
        return Err(PersistenceError::Corrupt);
    }
    let effect = keys
        .open(
            scope,
            &record.key,
            &aad(scope, &record.key, record.revision, operation_id, 1),
            &record.effect,
        )
        .map_err(PersistenceError::Key)?;
    if effect.len() > MAX_BLOB {
        return Err(PersistenceError::Corrupt);
    }
    Ok(Some(effect))
}
