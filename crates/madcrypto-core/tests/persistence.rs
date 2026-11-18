//! Real AES-GCM software test provider, NOT a Keychain/Keystore/HUKS adapter.
use madcrypto_core::{persistence::*, session::SecureSession, x3dh::*};
use madcrypto_prims::{CipherSuite, IntlSuite as Suite};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use std::collections::HashMap;
use zeroize::Zeroizing;

struct Keys {
    key: Zeroizing<[u8; 32]>,
    live: bool,
    locked: bool,
    rng: ChaCha20Rng,
}
impl Keys {
    fn new() -> Self {
        Self {
            key: Zeroizing::new([7; 32]),
            live: true,
            locked: false,
            rng: ChaCha20Rng::seed_from_u64(543),
        }
    }
}
impl PlatformKeyStore for Keys {
    fn create(
        &mut self,
        _: &Scope,
        _: &KeyRef,
        policy: KeyPolicy,
    ) -> Result<KeyProtection, KeyError> {
        if policy.minimum != KeyProtection::Software || policy.user_presence {
            return Err(KeyError::Unsupported);
        }
        if self.live {
            return Err(KeyError::Denied);
        }
        self.rng.fill_bytes(self.key.as_mut());
        self.live = true;
        Ok(KeyProtection::Software)
    }
    fn delete(&mut self, _: &Scope, _: &KeyRef) -> Result<(), KeyError> {
        self.live = false;
        Ok(())
    }
    fn seal(&mut self, _: &Scope, _: &KeyRef, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, KeyError> {
        if self.locked {
            return Err(KeyError::Locked);
        }
        if !self.live {
            return Err(KeyError::NotFound);
        }
        let mut nonce = [0; 12];
        self.rng.fill_bytes(&mut nonce);
        let mut out = nonce.to_vec();
        out.extend(Suite::aead_seal(&self.key, &nonce, aad, pt));
        Ok(out)
    }
    fn open(
        &mut self,
        _: &Scope,
        _: &KeyRef,
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if self.locked {
            return Err(KeyError::Locked);
        }
        if !self.live {
            return Err(KeyError::NotFound);
        }
        if ct.len() < 12 {
            return Err(KeyError::Authentication);
        }
        Suite::aead_open(&self.key, ct[..12].try_into().unwrap(), aad, &ct[12..])
            .map(Zeroizing::new)
            .map_err(|_| KeyError::Authentication)
    }
}
#[derive(Default)]
struct Store {
    records: HashMap<Scope, SealedCommit>,
    operations: HashMap<(Scope, String), SealedCommit>,
    next: Option<CommitOutcome>,
    fail_read: bool,
    panic_after_write: bool,
    unknown_no_write: bool,
}
impl AtomicSessionStore for Store {
    fn load(&mut self, s: &Scope) -> Result<Option<SealedCommit>, PersistenceError> {
        if self.fail_read {
            Err(PersistenceError::StoreUnavailable)
        } else {
            Ok(self.records.get(s).cloned())
        }
    }
    fn load_operation(
        &mut self,
        s: &Scope,
        id: &str,
    ) -> Result<Option<SealedCommit>, PersistenceError> {
        if self.fail_read {
            Err(PersistenceError::StoreUnavailable)
        } else {
            Ok(self.operations.get(&(s.clone(), id.into())).cloned())
        }
    }
    fn commit(&mut self, expected: Option<u64>, w: SealedCommit) -> CommitOutcome {
        if self.records.get(&w.scope).map(|r| r.revision) != expected
            || self
                .operations
                .contains_key(&(w.scope.clone(), w.operation_id.clone()))
        {
            return CommitOutcome::Conflict;
        }
        let outcome = self.next.take().unwrap_or(CommitOutcome::Committed);
        if outcome == CommitOutcome::Committed
            || (outcome == CommitOutcome::Unknown && !self.unknown_no_write)
        {
            self.operations
                .insert((w.scope.clone(), w.operation_id.clone()), w.clone());
            self.records.insert(w.scope.clone(), w);
        }
        assert!(
            !self.panic_after_write,
            "injected failure after durable write"
        );
        outcome
    }
}
fn fixture() -> (
    PersistentSession,
    SecureSession,
    ChaCha20Rng,
    Scope,
    KeyRef,
    Keys,
    Store,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(19);
    let a = generate_identity::<Suite, _>(&mut rng);
    let b = generate_identity::<Suite, _>(&mut rng);
    let (sk, pk, sig) = new_signed_prekey::<Suite, _>(&mut rng, &b).unwrap();
    let bundle = PreKeyBundle {
        suite: Suite::id(),
        identity: b.public(),
        signed_prekey: pk,
        signed_prekey_sig: sig,
        one_time_prekey: None,
    };
    let init = initiate::<Suite, _>(&mut rng, &a, &bundle).unwrap();
    let resp = respond::<Suite>(
        ResponderKeys {
            identity: &b,
            signed_prekey_private: &sk,
            one_time_prekey_private: None,
        },
        &init.initial_message,
    )
    .unwrap();
    let alice =
        SecureSession::initiator::<Suite, _>(&mut rng, init.root, init.their_ratchet_public)
            .unwrap();
    let bob = SecureSession::receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public);
    let scope = Scope::new("app", "account", "session").unwrap();
    let key = KeyRef::new("session-key", 1).unwrap();
    (
        PersistentSession::new(scope.clone(), key.clone(), bob),
        alice,
        rng,
        scope,
        key,
        Keys::new(),
        Store::default(),
    )
}
#[test]
fn encrypted_receive_roundtrip_reload_and_effect_recovery() {
    let (mut session, mut alice, mut rng, scope, _, mut keys, mut store) = fixture();
    let (h, ct) = alice.encrypt::<Suite>(b"ad", b"private message").unwrap();
    assert_eq!(
        &**session
            .update(&mut store, &mut keys, "op-1", |s| s
                .decrypt::<Suite, _>(&mut rng, &h, &ct, b"ad"))
            .unwrap(),
        b"private message"
    );
    assert_eq!(session.revision(), Some(1));
    let row = store.records.get(&scope).unwrap();
    assert!(!row.effect.windows(15).any(|w| w == b"private message"));
    assert_eq!(
        &**recover_effect(&mut store, &mut keys, &scope, "op-1")
            .unwrap()
            .unwrap(),
        b"private message"
    );
    let mut reloaded = PersistentSession::load(&mut store, &mut keys, scope)
        .unwrap()
        .unwrap();
    let (h, ct) = alice.encrypt::<Suite>(b"ad", b"next").unwrap();
    assert_eq!(
        &**reloaded
            .update(&mut store, &mut keys, "op-2", |s| s
                .decrypt::<Suite, _>(&mut rng, &h, &ct, b"ad"))
            .unwrap(),
        b"next"
    );
}
#[test]
fn definite_failure_and_locked_key_do_not_advance_session() {
    let (mut session, mut alice, mut rng, _, _, mut keys, mut store) = fixture();
    let (h, ct) = alice.encrypt::<Suite>(b"", b"retry").unwrap();
    keys.locked = true;
    assert_eq!(
        session
            .update(&mut store, &mut keys, "op", |s| s
                .decrypt::<Suite, _>(&mut rng, &h, &ct, b""))
            .unwrap_err(),
        PersistenceError::Key(KeyError::Locked)
    );
    assert_eq!(session.revision(), None);
    keys.locked = false;
    store.next = Some(CommitOutcome::Rejected);
    assert_eq!(
        session
            .update(&mut store, &mut keys, "op", |s| s
                .decrypt::<Suite, _>(&mut rng, &h, &ct, b""))
            .unwrap_err(),
        PersistenceError::Rejected
    );
    assert_eq!(session.revision(), None);
    assert_eq!(
        &**session
            .update(&mut store, &mut keys, "op", |s| s
                .decrypt::<Suite, _>(&mut rng, &h, &ct, b""))
            .unwrap(),
        b"retry"
    );
}
#[test]
fn uncertain_commit_freezes_until_authoritative_reload() {
    let (mut session, mut alice, mut rng, scope, _, mut keys, mut store) = fixture();
    let (h, ct) = alice.encrypt::<Suite>(b"", b"once").unwrap();
    store.next = Some(CommitOutcome::Unknown);
    assert_eq!(
        session
            .update(&mut store, &mut keys, "op", |s| s
                .decrypt::<Suite, _>(&mut rng, &h, &ct, b""))
            .unwrap_err(),
        PersistenceError::RecoveryRequired
    );
    assert!(session.recovery_required());
    assert_eq!(
        session
            .update(&mut store, &mut keys, "other", |_| panic!("must not run"))
            .unwrap_err(),
        PersistenceError::RecoveryRequired
    );
    assert_eq!(
        &**recover_effect(&mut store, &mut keys, &scope, "op")
            .unwrap()
            .unwrap(),
        b"once"
    );
    assert_eq!(
        PersistentSession::load(&mut store, &mut keys, scope)
            .unwrap()
            .unwrap()
            .revision(),
        Some(1)
    );
}
#[test]
fn stale_writer_cas_and_duplicate_operation_are_rejected() {
    let (mut first, _, _, scope, _, mut keys, mut store) = fixture();
    first
        .update(&mut store, &mut keys, "initial", |_| Ok(vec![]))
        .unwrap();
    let mut stale = PersistentSession::load(&mut store, &mut keys, scope)
        .unwrap()
        .unwrap();
    first
        .update(&mut store, &mut keys, "new", |_| Ok(vec![]))
        .unwrap();
    assert_eq!(
        stale
            .update(&mut store, &mut keys, "stale", |_| Ok(vec![]))
            .unwrap_err(),
        PersistenceError::Conflict
    );
    assert!(stale.recovery_required());
    assert_eq!(
        first
            .update(&mut store, &mut keys, "new", |_| Ok(vec![]))
            .unwrap_err(),
        PersistenceError::Conflict
    );
}
#[test]
fn scope_revision_and_ciphertext_tamper_fail_authentication() {
    let (mut session, _, _, scope, _, mut keys, mut store) = fixture();
    session
        .update(&mut store, &mut keys, "op", |_| Ok(vec![]))
        .unwrap();
    let original = store.records.get(&scope).unwrap().clone();
    store.records.get_mut(&scope).unwrap().revision += 1;
    assert!(matches!(
        PersistentSession::load(&mut store, &mut keys, scope.clone()),
        Err(PersistenceError::Key(KeyError::Authentication))
    ));
    store.records.insert(scope.clone(), original.clone());
    store.records.get_mut(&scope).unwrap().state[15] ^= 1;
    assert!(matches!(
        PersistentSession::load(&mut store, &mut keys, scope.clone()),
        Err(PersistenceError::Key(KeyError::Authentication))
    ));
    let other = Scope::new("other-app", "account", "session").unwrap();
    let mut switched = original;
    switched.scope = other.clone();
    store.records.insert(other.clone(), switched);
    assert!(matches!(
        PersistentSession::load(&mut store, &mut keys, other),
        Err(PersistenceError::Key(KeyError::Authentication))
    ));
}
#[test]
fn key_deletion_and_io_error_never_look_like_new_session() {
    let (mut session, _, _, scope, key, mut keys, mut store) = fixture();
    session
        .update(&mut store, &mut keys, "op", |_| Ok(vec![]))
        .unwrap();
    keys.delete(&scope, &key).unwrap();
    assert!(matches!(
        PersistentSession::load(&mut store, &mut keys, scope.clone()),
        Err(PersistenceError::Key(KeyError::NotFound))
    ));
    store.fail_read = true;
    assert!(matches!(
        PersistentSession::load(&mut store, &mut keys, scope),
        Err(PersistenceError::StoreUnavailable)
    ));
}
#[test]
fn hardware_requirement_cannot_silently_fallback() {
    let (_, _, _, scope, key, mut keys, _) = fixture();
    assert_eq!(
        keys.create(
            &scope,
            &key,
            KeyPolicy {
                minimum: KeyProtection::HardwareBacked,
                user_presence: false
            }
        ),
        Err(KeyError::Unsupported)
    );
}
#[test]
fn validate_scope_and_key_names() {
    assert!(Scope::new("", "a", "s").is_err());
    assert!(Scope::new("app", "a\n", "s").is_err());
    assert!(KeyRef::new("key", 0).is_err());
}

#[test]
fn effect_metadata_and_role_swaps_are_authenticated() {
    let (mut session, _, _, scope, _, mut keys, mut store) = fixture();
    session
        .update(&mut store, &mut keys, "op", |_| Ok(b"effect".to_vec()))
        .unwrap();
    let original = store
        .operations
        .get(&(scope.clone(), "op".into()))
        .unwrap()
        .clone();
    let mut swapped = original.clone();
    swapped.effect = swapped.state.clone();
    store
        .operations
        .insert((scope.clone(), "op".into()), swapped);
    assert_eq!(
        recover_effect(&mut store, &mut keys, &scope, "op").unwrap_err(),
        PersistenceError::Key(KeyError::Authentication)
    );
    let mut changed = original;
    changed.key = KeyRef::new("wrong-alias", 1).unwrap();
    store
        .operations
        .insert((scope.clone(), "op".into()), changed);
    assert_eq!(
        recover_effect(&mut store, &mut keys, &scope, "op").unwrap_err(),
        PersistenceError::Key(KeyError::Authentication)
    );
}

#[test]
fn oversized_effect_and_protocol_failure_do_not_commit() {
    let (mut session, _, _, _, _, mut keys, mut store) = fixture();
    assert_eq!(
        session
            .update(&mut store, &mut keys, "oversized", |_| Ok(vec![
                0;
                1024 * 1024
                    + 1
            ]))
            .unwrap_err(),
        PersistenceError::Invalid
    );
    assert_eq!(session.revision(), None);
    assert!(store.records.is_empty());
    assert_eq!(
        session
            .update(&mut store, &mut keys, "failed", |_| Err(
                madcrypto_core::CryptoError::Malformed
            ))
            .unwrap_err(),
        PersistenceError::Protocol
    );
    assert!(store.operations.is_empty());
}

#[test]
fn host_commit_panic_keeps_recovery_barrier() {
    let (mut session, _, _, scope, _, mut keys, mut store) = fixture();
    store.panic_after_write = true;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.update(&mut store, &mut keys, "op", |_| Ok(b"durable".to_vec()))
    }));
    assert!(panic.is_err());
    assert!(session.recovery_required());
    assert_eq!(
        session
            .update(&mut store, &mut keys, "next", |_| panic!("must not run"))
            .unwrap_err(),
        PersistenceError::RecoveryRequired
    );
    assert_eq!(
        &**recover_effect(&mut store, &mut keys, &scope, "op")
            .unwrap()
            .unwrap(),
        b"durable"
    );
}

#[test]
fn sender_unknown_recovers_exact_ciphertext_then_advances_once() {
    use madcrypto_core::wire;
    let (mut receiver, alice, mut rng, _, key, mut keys, mut receiver_store) = fixture();
    let scope = Scope::new("app", "sender", "session").unwrap();
    let mut sender = PersistentSession::new(scope.clone(), key, alice);
    let mut sender_store = Store {
        next: Some(CommitOutcome::Unknown),
        ..Store::default()
    };
    let mut expected = Vec::new(); // Fixture only: never publish work output before commit.
    assert_eq!(
        sender
            .update(&mut sender_store, &mut keys, "send-1", |s| {
                let (header, ct) = s.encrypt::<Suite>(b"ad", b"first")?;
                expected = wire::encode_message(Suite::id(), &header, &ct);
                Ok(expected.clone())
            })
            .unwrap_err(),
        PersistenceError::RecoveryRequired
    );
    let recovered = recover_effect(&mut sender_store, &mut keys, &scope, "send-1")
        .unwrap()
        .unwrap();
    assert_eq!(&*recovered, &expected);
    let (_, h1, ct1) = wire::decode_message(&recovered).unwrap();
    assert_eq!(
        &**receiver
            .update(&mut receiver_store, &mut keys, "receive-1", |s| s
                .decrypt::<Suite, _>(&mut rng, &h1, &ct1, b"ad"))
            .unwrap(),
        b"first"
    );
    let mut sender = PersistentSession::load(&mut sender_store, &mut keys, scope)
        .unwrap()
        .unwrap();
    let second = sender
        .update(&mut sender_store, &mut keys, "send-2", |s| {
            let (header, ct) = s.encrypt::<Suite>(b"ad", b"second")?;
            Ok(wire::encode_message(Suite::id(), &header, &ct))
        })
        .unwrap();
    let (_, h2, ct2) = wire::decode_message(&second).unwrap();
    assert_eq!(h2.dh.as_slice(), h1.dh.as_slice());
    assert_eq!(h2.n, h1.n + 1);
    assert_ne!(second.as_slice(), recovered.as_slice());
    assert_eq!(
        &**receiver
            .update(&mut receiver_store, &mut keys, "receive-2", |s| s
                .decrypt::<Suite, _>(&mut rng, &h2, &ct2, b"ad"))
            .unwrap(),
        b"second"
    );
}

#[test]
fn unknown_without_write_requires_reload_before_retry() {
    let (mut session, mut alice, mut rng, scope, _, mut keys, mut store) = fixture();
    session
        .update(&mut store, &mut keys, "initial", |_| Ok(vec![]))
        .unwrap();
    let (header, ct) = alice
        .encrypt::<Suite>(b"", b"retry after recovery")
        .unwrap();
    store.next = Some(CommitOutcome::Unknown);
    store.unknown_no_write = true;
    assert_eq!(
        session
            .update(&mut store, &mut keys, "op", |s| s
                .decrypt::<Suite, _>(&mut rng, &header, &ct, b""))
            .unwrap_err(),
        PersistenceError::RecoveryRequired
    );
    assert!(session.recovery_required());
    assert!(recover_effect(&mut store, &mut keys, &scope, "op")
        .unwrap()
        .is_none());
    let mut recovered = PersistentSession::load(&mut store, &mut keys, scope)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.revision(), Some(1));
    assert_eq!(
        &**recovered
            .update(&mut store, &mut keys, "op", |s| s
                .decrypt::<Suite, _>(&mut rng, &header, &ct, b""))
            .unwrap(),
        b"retry after recovery"
    );
    assert_eq!(recovered.revision(), Some(2));
}
