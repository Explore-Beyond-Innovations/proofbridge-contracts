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

/// ed25519 agent: a bad signature traps in the host (the host turns that into
/// an auth failure); a good one yields the pubkey as the agent id.
pub fn verify_ed25519(env: &Env, payload: &Hash<32>, s: &Ed25519Sig) -> AgentId {
    let msg: Bytes = payload.to_bytes().into();
    env.crypto().ed25519_verify(&s.pubkey, &msg, &s.sig);
    s.pubkey.clone()
}

/// secp256k1 agent: recovery yields some address, and a wrong signer simply
/// has no policy. Only an out-of-range recovery id is `BadSignature`.
pub fn verify_secp(env: &Env, payload: &Hash<32>, s: &SecpSig) -> Result<AgentId, AccountError> {
    let addr = proofbridge_core::secp::recover_evm_address(env, payload, &s.sig, s.recovery_id)
        .ok_or(AccountError::BadSignature)?;
    Ok(proofbridge_core::secp::evm_address_to_bytes32(env, &addr))
}
