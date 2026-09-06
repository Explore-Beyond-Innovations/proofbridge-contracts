//! Signature shapes `__check_auth` consumes and the agent-id derivation.

use soroban_sdk::{contracttype, crypto::Hash, Bytes, BytesN, Env};

use crate::errors::AccountError;
use crate::policy::AgentId;

#[contracttype]
#[derive(Clone, Debug)]
pub struct Ed25519Sig {
    pub pubkey: BytesN<32>,
    pub sig: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct SecpSig {
    /// r || s
    pub sig: BytesN<64>,
    /// 0/1 (27/28 also accepted)
    pub recovery_id: u32,
}

/// `Owner`: the owner address authorizes `__check_auth(payload)` itself (a
/// nested auth entry). `Agent*`: the agent signs the raw 32-byte Soroban
/// payload; no EIP-191 prefix on the secp path.
#[contracttype]
#[derive(Clone, Debug)]
pub enum AccountSig {
    Owner,
    Agent(Ed25519Sig),
    AgentSecp(SecpSig),
}

/// Verify the agent signature over the payload and return the agent id it
/// belongs to. ed25519 verification traps on a bad signature (the host turns
/// that into an auth failure); secp recovery yields some address, and a wrong
/// signer simply has no policy.
pub fn verify_agent(
    env: &Env,
    payload: &Hash<32>,
    sig: &AccountSig,
) -> Result<AgentId, AccountError> {
    match sig {
        AccountSig::Owner => Err(AccountError::BadSignature),
        AccountSig::Agent(s) => {
            let msg: Bytes = payload.to_bytes().into();
            env.crypto().ed25519_verify(&s.pubkey, &msg, &s.sig);
            Ok(s.pubkey.clone())
        }
        AccountSig::AgentSecp(s) => {
            let v = if s.recovery_id >= 27 {
                s.recovery_id - 27
            } else {
                s.recovery_id
            };
            if v > 1 {
                return Err(AccountError::BadSignature);
            }
            let pubkey = env.crypto().secp256k1_recover(payload, &s.sig, v);
            let pk = pubkey.to_array();
            let addr_hash = env
                .crypto()
                .keccak256(&Bytes::from_slice(env, &pk[1..]))
                .to_array();
            let mut id = [0u8; 32];
            id[12..].copy_from_slice(&addr_hash[12..]);
            Ok(BytesN::from_array(env, &id))
        }
    }
}
