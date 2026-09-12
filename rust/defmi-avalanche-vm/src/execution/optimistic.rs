//! Canonical host for the shared optimistic protocol. All changes execute on
//! the VM candidate state and commit with its existing consensus transaction.
//! Proposals cannot enroll their own policy or choose their own input snapshot.
use super::*;
use zkpi_committee::optimistic::{
    ApplicationAuthentication, Challenge, ChallengeVerifier, OptimisticPolicy, Proposal,
    QuoteChallengeVerifier, RegisteredExecution,
};

use zkpi_committee::optimistic::{command_digest as statement, BondTransfer};

pub(super) fn enroll(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    application: &dyn crate::application::ApplicationRuntime,
) -> Result<[u8; 32], String> {
    require_keys(params, &["policy", "approval", "expectedBeforeRoot"])?;
    let policy: OptimisticPolicy = field(params, "policy")?;
    if policy.verifier != QuoteChallengeVerifier.verifier_id() {
        if application
            .optimistic_verifier(policy.verifier)?
            .verifier_id()
            != policy.verifier
        {
            return Err("optimistic policy has no installed canonical challenge verifier".into());
        }
    }
    if !state
        .assets
        .get(&id_key(&policy.bond_asset))
        .is_some_and(|asset| asset.active)
    {
        return Err("optimistic collateral asset is not active".into());
    }
    let digest = statement("enroll", &policy)?;
    authorize(state, params, digest, authorizer)?;
    state.optimistic.enroll_policy(policy)?;
    Ok(digest)
}

pub(super) fn register(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["execution", "approval", "expectedBeforeRoot"])?;
    let execution: RegisteredExecution = field(params, "execution")?;
    if execution.context.before_state != state.root() {
        return Err("optimistic execution snapshot is not the canonical parent".into());
    }
    let digest = statement("register", &execution)?;
    authorize(state, params, digest, authorizer)?;
    state.optimistic.register_execution(execution)?;
    Ok(digest)
}

/// An explicitly public collateral account, controlled by the existing
/// governance account-opening authorization. It is debited atomically: escrow
/// funding never creates assets or alters a customer's confidential note.

pub(super) fn bond(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["transfer", "approval", "expectedBeforeRoot"])?;
    let transfer: BondTransfer = field(params, "transfer")?;
    if transfer.amount == 0 || transfer.owner == ZERO {
        return Err("optimistic bond transfer is empty".into());
    }
    let digest = statement("bond", &transfer)?;
    authorize(state, params, digest, authorizer)?;
    let id = id_key(&transfer.owner);
    let account = state
        .accounts
        .get(&id)
        .ok_or("optimistic collateral account is absent")?;
    if account.asset_id != transfer.asset
        || !state
            .assets
            .get(&id_key(&transfer.asset))
            .is_some_and(|a| a.active)
    {
        return Err("optimistic collateral account has another or inactive asset".into());
    }
    let blind = Option::<Scalar>::from(Scalar::from_canonical_bytes(transfer.blinding))
        .ok_or("bond blinding is not canonical")?;
    let key = Pedersen::new(b"qomm:defmi:v1");
    if key
        .commit(&Scalar::from(transfer.before_balance), &blind)
        .compress()
        .to_bytes()
        != account.commitment
    {
        return Err("optimistic bond funding does not open the current account balance".into());
    }
    let after = if transfer.withdraw {
        transfer
            .before_balance
            .checked_add(transfer.amount)
            .ok_or("bond withdrawal balance overflow")?
    } else {
        transfer
            .before_balance
            .checked_sub(transfer.amount)
            .ok_or("insufficient collateral account balance")?
    };
    let sequence = account
        .sequence
        .checked_add(1)
        .ok_or("collateral sequence overflow")?;
    if transfer.withdraw {
        state
            .optimistic
            .withdraw_escrow(transfer.asset, transfer.owner, transfer.amount)?;
    } else {
        state
            .optimistic
            .credit_escrow(transfer.asset, transfer.owner, transfer.amount)?;
    }
    let account = state
        .accounts
        .get_mut(&id)
        .ok_or("collateral account disappeared")?;
    account.commitment = key
        .commit(&Scalar::from(after), &blind)
        .compress()
        .to_bytes();
    account.sequence = sequence;
    Ok(digest)
}

pub(super) fn propose(
    state: &mut State,
    params: &Map<String, Value>,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["proposal"])?;
    let proposal: Proposal = field(params, "proposal")?;
    state
        .optimistic
        .propose(proposal, now, &ApplicationAuthentication)
}

pub(super) fn challenge(
    state: &mut State,
    params: &Map<String, Value>,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["challenge"])?;
    let challenge: Challenge = field(params, "challenge")?;
    let digest = statement("challenge", &challenge)?;
    state
        .optimistic
        .challenge(challenge, now, &ApplicationAuthentication)?;
    Ok(digest)
}

pub(super) fn answer(
    state: &mut State,
    params: &Map<String, Value>,
    now: u64,
    application: &dyn crate::application::ApplicationRuntime,
) -> Result<[u8; 32], String> {
    require_keys(params, &["claim", "proof", "attempt"])?;
    let attempt: [u8; 32] = field(params, "attempt")?;
    if attempt == ZERO {
        return Err("optimistic answer attempt is empty".into());
    }
    let claim: [u8; 32] = field(params, "claim")?;
    let encoded: String = field(params, "proof")?;
    if encoded.len() > 8 * 1024 * 1024 {
        return Err("optimistic answer is too large".into());
    }
    let proof = BASE64
        .decode(encoded)
        .map_err(|_| "optimistic answer is not base64")?;
    let digest = statement("answer", &(claim, hex::encode(Sha256::digest(&proof))))?;
    let verifier = state
        .optimistic
        .claim(&claim)
        .ok_or("unknown optimistic claim")?
        .policy
        .verifier;
    if verifier == QuoteChallengeVerifier.verifier_id() {
        state
            .optimistic
            .answer(claim, &proof, &QuoteChallengeVerifier, now)?;
    } else {
        let installed = application.optimistic_verifier(verifier)?;
        state
            .optimistic
            .answer(claim, &proof, installed.as_ref(), now)?;
    }
    Ok(digest)
}

pub(super) fn advance(
    state: &mut State,
    params: &Map<String, Value>,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["claim", "attempt"])?;
    let attempt: [u8; 32] = field(params, "attempt")?;
    if attempt == ZERO {
        return Err("optimistic advance attempt is empty".into());
    }
    let claim: [u8; 32] = field(params, "claim")?;
    state.optimistic.advance(claim, now)?;
    statement("advance", &claim)
}
