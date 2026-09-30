//! The owner's key messages, shared with the EVM registry (2.6 plan 13, D1–D5): one signature over
//! RegisterKey / RevokeKeys / RetireKey names every registry it is for. secp256k1 owners sign the
//! EIP-712 form, ed25519 owners the fixed text (SEP-53). Pinned by bls-encodings.json `ownerAuth`.

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, String, Vec};

use proofbridge_core::eip712::{
    abi_encode_uint256, address_to_bytes32, contract_address_to_bytes32,
};

use crate::errors::RegistryError;
use crate::storage;

/// keccak256("KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)")
pub(crate) const KEY_LEG_TYPEHASH: [u8; 32] = [
    0xfa, 0x75, 0xaf, 0x9d, 0x4f, 0x7f, 0x23, 0x32, 0x33, 0xf7, 0x04, 0x6e, 0x92, 0x9e, 0xf4, 0x0c,
    0xd6, 0xd1, 0x7e, 0xe3, 0xc0, 0xf5, 0x79, 0xae, 0xae, 0x91, 0xb2, 0xc8, 0x69, 0x7b, 0x95, 0x99,
];
/// keccak256("RegisterKey(bytes32 account,bytes32 keyCommitment,KeyLeg[] legs,uint64 deadline)KeyLeg(...)")
pub(crate) const REGISTER_KEY_TYPEHASH: [u8; 32] = [
    0x86, 0xb4, 0xf5, 0xa5, 0xd0, 0x73, 0x5e, 0x9a, 0x7a, 0x9e, 0xb9, 0xdf, 0xa3, 0x2f, 0x81, 0x36,
    0x4b, 0x16, 0x02, 0xf5, 0x09, 0x8d, 0x95, 0x18, 0x2d, 0xa5, 0x06, 0xee, 0xf7, 0x02, 0x7c, 0x92,
];
/// keccak256("RevokeKeys(bytes32 account,KeyLeg[] legs)KeyLeg(...)")
pub(crate) const REVOKE_KEYS_TYPEHASH: [u8; 32] = [
    0xd2, 0xcc, 0x96, 0x44, 0xd4, 0xc5, 0xbc, 0xcc, 0xcd, 0x70, 0x6c, 0xaf, 0xc5, 0x8d, 0x84, 0x44,
    0x9d, 0x6f, 0x6d, 0x11, 0x32, 0x97, 0xaa, 0x87, 0x8f, 0x49, 0xd2, 0x4a, 0xc6, 0x72, 0xa8, 0x25,
];
/// keccak256("RetireKey(bytes32 account,bytes32 keyCommitment,uint64 validUntil)")
pub(crate) const RETIRE_KEY_TYPEHASH: [u8; 32] = [
    0x1a, 0xbc, 0x6d, 0xf0, 0x38, 0xc1, 0x82, 0xce, 0x09, 0x98, 0x12, 0x1f, 0x30, 0x6e, 0x7b, 0xd9,
    0xa9, 0xf4, 0xb4, 0xa0, 0x10, 0xfc, 0x40, 0xd9, 0x09, 0x30, 0x8c, 0x8e, 0x77, 0xcb, 0x90, 0xfd,
];

const SEP53_PREFIX: &[u8; 24] = b"Stellar Signed Message:\n";
/// D2: a RegisterKey deadline may sit at most this far past ledger time.
pub(crate) const MAX_REGISTER_TTL: u64 = 7 * 24 * 3600;
/// D3: the environments a registry is initialized for.
const KEYS_ENVS: [&[u8]; 3] = [b"local", b"testnet", b"mainnet"];
const REGISTER_HEADING: &[u8] = b"ProofBridge: register a settlement key";
const REVOKE_HEADING: &[u8] = b"ProofBridge: remove every settlement key";
const RETIRE_HEADING: &[u8] = b"ProofBridge: retire a settlement key";

/// One registry a signature is for: its chain, its 32-byte id and its nonce for the account.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLeg {
    pub chain_id: u128,
    pub registry: BytesN<32>,
    pub nonce: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub enum OwnerSig {
    /// `r || s || v` over the EIP-712 digest; the account is 12 zero bytes ‖ the signer's address.
    Secp256k1(BytesN<65>),
    /// Detached ed25519 over sha256("Stellar Signed Message:\n" ‖ text); the account is the key.
    Sep53(BytesN<64>),
}

/// The signed form. A contracttype enum variant cannot carry named fields, so it wraps this.
#[contracttype]
#[derive(Clone, Debug)]
pub struct SignedOwner {
    /// Every registry the signature names; `RetireKey` names none.
    pub legs: Vec<KeyLeg>,
    pub sig: OwnerSig,
}

/// How the account owner authorized this state change.
#[contracttype]
#[derive(Clone, Debug)]
pub enum OwnerAuth {
    /// `require_auth`; the address must resolve to `account`. Covers this registry only.
    Stellar(Address),
    /// One owner signature over the shared message.
    Signed(SignedOwner),
}

/// The message a state change needs signed.
pub(crate) enum KeyMessage {
    Register {
        fingerprint: BytesN<32>,
        nonce: u64,
        deadline: u64,
    },
    Revoke {
        nonce: u64,
    },
    Retire {
        fingerprint: BytesN<32>,
        valid_until: u64,
    },
}

/// D3: the env's bytes, if it is one of local / testnet / mainnet.
fn env_bytes(name: &String) -> Option<([u8; 7], usize)> {
    let len = name.len() as usize;
    if len > 7 {
        return None;
    }
    let mut buf = [0u8; 7];
    name.copy_into_slice(&mut buf[..len]);
    KEYS_ENVS
        .iter()
        .any(|e| *e == &buf[..len])
        .then_some((buf, len))
}

/// D3: keccak(EIP712Domain(string name,string version,bytes32 salt) ‖ name ‖ version ‖ salt) with
/// salt = keccak256("proofbridge:" ‖ env); refuses any other environment.
pub(crate) fn keys_domain_separator(env: &Env, name: &String) -> Result<BytesN<32>, RegistryError> {
    let (buf, len) = env_bytes(name).ok_or(RegistryError::BadEnv)?;
    let mut salt_pre = Bytes::from_slice(env, b"proofbridge:");
    salt_pre.extend_from_slice(&buf[..len]);
    let mut enc = Bytes::from_slice(
        env,
        &keccak(
            env,
            &Bytes::from_slice(
                env,
                b"EIP712Domain(string name,string version,bytes32 salt)",
            ),
        ),
    );
    enc.extend_from_slice(&keccak(env, &Bytes::from_slice(env, b"ProofBridge Keys")));
    enc.extend_from_slice(&keccak(env, &Bytes::from_slice(env, b"2")));
    enc.extend_from_slice(&keccak(env, &salt_pre));
    Ok(BytesN::from_array(env, &keccak(env, &enc)))
}

/// D2: keccak256 of the key's EIP-2537 128-byte form, rebuilt by padding each 48-byte coordinate
/// of the 96-byte key with 16 zero bytes. Same value as the EVM registry's commitment.
pub(crate) fn key_fingerprint(env: &Env, pk: &BytesN<96>) -> BytesN<32> {
    let raw = pk.to_array();
    let mut padded = [0u8; 128];
    padded[16..64].copy_from_slice(&raw[..48]);
    padded[80..128].copy_from_slice(&raw[48..]);
    env.crypto()
        .keccak256(&Bytes::from_slice(env, &padded))
        .to_bytes()
}

pub(crate) fn check_owner(
    env: &Env,
    account: &BytesN<32>,
    owner: OwnerAuth,
    msg: KeyMessage,
) -> Result<(), RegistryError> {
    match owner {
        OwnerAuth::Stellar(addr) => {
            addr.require_auth();
            if address_to_bytes32(env, &addr) != *account {
                return Err(RegistryError::OwnerMismatch);
            }
            Ok(())
        }
        OwnerAuth::Signed(s) => {
            check_legs(env, &s.legs, &msg)?;
            match s.sig {
                OwnerSig::Secp256k1(sig) => check_secp256k1(env, account, &s.legs, &msg, &sig),
                OwnerSig::Sep53(sig) => check_sep53(env, account, &s.legs, &msg, &sig),
            }
        }
    }
}

/// D5 check 1: exactly one entry names this registry (whatever its nonce, review 50-3) and it
/// carries the current nonce; a retirement names none.
fn check_legs(env: &Env, legs: &Vec<KeyLeg>, msg: &KeyMessage) -> Result<(), RegistryError> {
    let nonce = match msg {
        KeyMessage::Register { nonce, .. } | KeyMessage::Revoke { nonce } => *nonce,
        KeyMessage::Retire { .. } => {
            return if legs.is_empty() {
                Ok(())
            } else {
                Err(RegistryError::LegMismatch)
            };
        }
    };
    let chain_id = storage::get_chain_id(env);
    let registry = contract_address_to_bytes32(env);
    let mut mine = legs
        .iter()
        .filter(|l| l.chain_id == chain_id && l.registry == registry);
    match (mine.next(), mine.next()) {
        (Some(l), None) if l.nonce == nonce => Ok(()),
        _ => Err(RegistryError::LegMismatch),
    }
}

/// `account` must be 12 zero bytes || the address recovered from the EIP-712 digest.
fn check_secp256k1(
    env: &Env,
    account: &BytesN<32>,
    legs: &Vec<KeyLeg>,
    msg: &KeyMessage,
    sig: &BytesN<65>,
) -> Result<(), RegistryError> {
    let acct = account.to_array();
    if acct[..12].iter().any(|b| *b != 0) {
        return Err(RegistryError::OwnerMismatch);
    }
    let mut prefixed = Bytes::from_slice(env, &[0x19, 0x01]);
    prefixed.extend_from_slice(&storage::get_domain(env).to_array());
    prefixed.extend_from_slice(&struct_hash(env, account, legs, msg));
    let digest = env.crypto().keccak256(&prefixed);

    let sig_arr = sig.to_array();
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&sig_arr[..64]);
    let addr = proofbridge_core::secp::recover_evm_address(
        env,
        &digest,
        &BytesN::from_array(env, &rs),
        sig_arr[64] as u32,
    )
    .ok_or(RegistryError::OwnerMismatch)?;
    if addr[..] != acct[12..] {
        return Err(RegistryError::OwnerMismatch);
    }
    Ok(())
}

/// `account` is the raw ed25519 key, never a padded EVM shape. The host's ed25519 verify traps on
/// a bad signature (there is no boolean form), so a wrong signer surfaces as a host error.
fn check_sep53(
    env: &Env,
    account: &BytesN<32>,
    legs: &Vec<KeyLeg>,
    msg: &KeyMessage,
    sig: &BytesN<64>,
) -> Result<(), RegistryError> {
    if account.to_array()[..12].iter().all(|b| *b == 0) {
        return Err(RegistryError::OwnerMismatch);
    }
    let mut message = Bytes::from_slice(env, SEP53_PREFIX);
    message.append(&text(env, account, legs, msg));
    let payload = env.crypto().sha256(&message).to_bytes();
    env.crypto()
        .ed25519_verify(account, &Bytes::from(payload), sig);
    Ok(())
}

// ---- EIP-712 ----

fn keccak(env: &Env, data: &Bytes) -> [u8; 32] {
    env.crypto().keccak256(data).to_array()
}

fn legs_hash(env: &Env, legs: &Vec<KeyLeg>) -> [u8; 32] {
    let mut all = Bytes::new(env);
    for l in legs.iter() {
        let mut enc = Bytes::from_slice(env, &KEY_LEG_TYPEHASH);
        enc.extend_from_slice(&abi_encode_uint256(l.chain_id));
        enc.extend_from_slice(&l.registry.to_array());
        enc.extend_from_slice(&abi_encode_uint256(l.nonce as u128));
        all.extend_from_slice(&keccak(env, &enc));
    }
    keccak(env, &all)
}

pub(crate) fn struct_hash(
    env: &Env,
    account: &BytesN<32>,
    legs: &Vec<KeyLeg>,
    msg: &KeyMessage,
) -> [u8; 32] {
    let mut enc = Bytes::new(env);
    match msg {
        KeyMessage::Register {
            fingerprint,
            deadline,
            ..
        } => {
            enc.extend_from_slice(&REGISTER_KEY_TYPEHASH);
            enc.extend_from_slice(&account.to_array());
            enc.extend_from_slice(&fingerprint.to_array());
            enc.extend_from_slice(&legs_hash(env, legs));
            enc.extend_from_slice(&abi_encode_uint256(*deadline as u128));
        }
        KeyMessage::Revoke { .. } => {
            enc.extend_from_slice(&REVOKE_KEYS_TYPEHASH);
            enc.extend_from_slice(&account.to_array());
            enc.extend_from_slice(&legs_hash(env, legs));
        }
        KeyMessage::Retire {
            fingerprint,
            valid_until,
        } => {
            enc.extend_from_slice(&RETIRE_KEY_TYPEHASH);
            enc.extend_from_slice(&account.to_array());
            enc.extend_from_slice(&fingerprint.to_array());
            enc.extend_from_slice(&abi_encode_uint256(*valid_until as u128));
        }
    }
    keccak(env, &enc)
}

// ---- the fixed text (D4) ----

/// Lines joined by "\n", no trailing newline; decimal numbers, full lowercase 0x hex.
pub(crate) fn text(env: &Env, account: &BytesN<32>, legs: &Vec<KeyLeg>, msg: &KeyMessage) -> Bytes {
    let mut t = Bytes::new(env);
    let heading = match msg {
        KeyMessage::Register { .. } => REGISTER_HEADING,
        KeyMessage::Revoke { .. } => REVOKE_HEADING,
        KeyMessage::Retire { .. } => RETIRE_HEADING,
    };
    t.extend_from_slice(heading);
    t.extend_from_slice(b"\n\nNetwork: ");
    let name = storage::get_keys_env(env);
    let (buf, len) = env_bytes(&name).unwrap_or(([0u8; 7], 0));
    t.extend_from_slice(&buf[..len]);
    t.extend_from_slice(b"\nAccount: ");
    t.extend_from_slice(&hex_0x_lower(&account.to_array()));
    match msg {
        KeyMessage::Register { fingerprint, .. } | KeyMessage::Retire { fingerprint, .. } => {
            t.extend_from_slice(b"\nKey fingerprint: ");
            t.extend_from_slice(&hex_0x_lower(&fingerprint.to_array()));
        }
        KeyMessage::Revoke { .. } => {}
    }
    if let KeyMessage::Register { deadline, .. } = msg {
        t.extend_from_slice(b"\nValid until: ");
        push_utc(&mut t, *deadline);
        t.extend_from_slice(b" (");
        push_decimal(&mut t, *deadline as u128);
        t.extend_from_slice(b")");
    }
    t.extend_from_slice(b"\n");
    match msg {
        KeyMessage::Retire { valid_until, .. } => {
            t.extend_from_slice(b"\nValid until: ");
            push_decimal(&mut t, *valid_until as u128);
        }
        _ => {
            for l in legs.iter() {
                t.extend_from_slice(b"\nChain ");
                push_decimal(&mut t, l.chain_id);
                t.extend_from_slice(b", registry ");
                t.extend_from_slice(&hex_0x_lower(&l.registry.to_array()));
                t.extend_from_slice(b", nonce ");
                push_decimal(&mut t, l.nonce as u128);
            }
        }
    }
    t
}

/// Unix seconds as "YYYY-MM-DD HH:MM:SS UTC" (Hinnant civil_from_days, as bls-encodings' utcText).
pub(crate) fn push_utc(t: &mut Bytes, unix: u64) {
    let tt = unix as u128;
    let (days, sod) = (tt / 86_400, tt % 86_400);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    push_padded(t, y, 4);
    t.push_back(b'-');
    push_padded(t, mo, 2);
    t.push_back(b'-');
    push_padded(t, d, 2);
    t.push_back(b' ');
    push_padded(t, sod / 3_600, 2);
    t.push_back(b':');
    push_padded(t, (sod % 3_600) / 60, 2);
    t.push_back(b':');
    push_padded(t, sod % 60, 2);
    t.extend_from_slice(b" UTC");
}

fn push_padded(t: &mut Bytes, v: u128, width: u32) {
    let mut p = 10u128.pow(width - 1);
    while v < p && p > 1 {
        t.push_back(b'0');
        p /= 10;
    }
    push_decimal(t, v);
}

fn push_decimal(t: &mut Bytes, mut v: u128) {
    let mut buf = [0u8; 39];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    t.extend_from_slice(&buf[i..]);
}

/// Lowercase "0x" + 64 hex.
fn hex_0x_lower(b: &[u8; 32]) -> [u8; 66] {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 66];
    out[0] = b'0';
    out[1] = b'x';
    for (i, byte) in b.iter().enumerate() {
        out[2 + i * 2] = ALPHABET[(byte >> 4) as usize];
        out[3 + i * 2] = ALPHABET[(byte & 0x0f) as usize];
    }
    out
}
