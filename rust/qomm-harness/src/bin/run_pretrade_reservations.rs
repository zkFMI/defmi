//! DeFMI-side acceptance of a closed QOMM pre-trade population.
//!
//! This executable is intentionally not a simulated quote engine. It reads the
//! private, seven-node-certified authority bundle, creates real zkPI-backed
//! asset escrows and confidential facility holds in `DefmiFacility`, consumes
//! every admission lane in its certified order, and returns a signed private
//! acknowledgement. Distinct wallet/TLS identities with the same anonymous
//! legal-entity commitment therefore contend on one authoritative facility.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey};
use qomm_defmi::asset_link::{prove as prove_asset_link, AssetLinkProof};
use qomm_defmi::avalanche::{
    AvalancheClient, AvalancheNoteBridge, AvalancheRpcClient, FacilityAvalancheBridge,
};
use qomm_defmi::facility::{
    reserve_handle_for, AccountOpening, AdmissionBatchPlan, AdmissionCommitteePlan,
    AdmissionSlotAdvance, AssetDefinition, AssetKind, CreditFacilityGrant,
    CreditFacilityRelationProof, CreditFacilityTransition, CreditTransitionKind, DefmiFacility,
    GuarantorDefinition, GuarantorKind, QuorumApproval, QuorumAuthorizer, ReservationAuthorization,
    ReservationEscrow, ReservationRole, ZERO,
};
use qomm_defmi::ledger::Ledger;
use qomm_defmi::note_chain::{
    CsdIssuerDefinition, NoteIssuance, NoteOutput, NoteReservationEscrow,
};
use qomm_defmi::notes::{NoteLedger, Wallet};
use qomm_defmi::product::{
    escrow_transfer_context, reserve_maker, reserve_taker, verify_maker_reservation,
    verify_note_reservation, verify_taker_reservation, IdentityEvidence, ReservationEscrowProof,
};
use qomm_defmi::settlement::{account_of, CASH_RAIL, SECURITIES_RAIL};
use qomm_defmi::settlement_verifier::SettlementVerifierConfig;
use qomm_transport::external_signer::{CommandEd25519Signer, Ed25519MessageSigner};
use qomm_transport::frost_cluster::{ReserveMandateRef, StdioFrostCluster};
use qomm_transport::mandate::Direction;
use qomm_transport::order::{verify_admission_lane, CertifiedAdmissionLane, OrderedAdmission};
use qomm_transport::pretrade_authority::{
    read_authority_private, write_ack_private, AcceptanceOpening, PretradeAcknowledgement,
    PretradeAuthorityBundle, PretradeReservationBinding, ReservationParty, TakerPretradeAuthority,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::typed::{
    AuthorizationScope, ExecutionContext, OperationKind, TradeDirection, TypedInstruction,
};
use qomm_zkpi::{typed_wire, Bounds, Issuer, Openings, Venue};
use rand_core::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn receipt_key() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"QOMM:ACCEPTANCE:DEFMI-RECEIPT-KEY:v1").into();
    SigningKey::from_bytes(&seed)
}

fn trusted_kyb_issuer() -> ed25519_dalek::VerifyingKey {
    let seed: [u8; 32] = Sha256::digest(b"QOMM:ACCEPTANCE:KYB-ISSUER-KEY:v1").into();
    SigningKey::from_bytes(&seed).verifying_key()
}

fn governance_keys() -> BTreeMap<String, SigningKey> {
    (0..7)
        .map(|node| {
            // Matches avalanche/defmivm/config/test-genesis.json and the
            // independent Avalanche acceptance harness. Production replaces
            // these acceptance-only deterministic keys in genesis.
            let seed: [u8; 32] = Sha256::digest(format!("key:{node}").as_bytes()).into();
            (format!("node-{node}"), SigningKey::from_bytes(&seed))
        })
        .collect()
}

fn authorizer(
    keys: &BTreeMap<String, SigningKey>,
    domain: &str,
) -> Result<QuorumAuthorizer, String> {
    QuorumAuthorizer::new(
        keys.iter()
            .map(|(node, key)| (node.clone(), key.verifying_key()))
            .collect(),
        3,
        1,
        domain,
    )
}

fn approve(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    statement: [u8; 32],
) -> Result<QuorumApproval, String> {
    let signers = keys
        .iter()
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    authorizer.approve(statement, facility.state_root()?, &signers)
}

fn approve_root(
    root: [u8; 32],
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    statement: [u8; 32],
) -> Result<QuorumApproval, String> {
    let signers = keys
        .iter()
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    authorizer.approve(statement, root, &signers)
}

fn credit_commit(amount: u64, blinding: &Scalar) -> [u8; 32] {
    Pedersen::new(b"qomm:defmi:credit-facility:v1")
        .commit_u64(amount, blinding)
        .compress()
        .to_bytes()
}

fn trade_direction(direction: Direction) -> TradeDirection {
    match direction {
        Direction::TakerBuys => TradeDirection::TakerBuys,
        Direction::TakerSells => TradeDirection::TakerSells,
    }
}

fn rail_for(kind: AssetKind) -> &'static [u8] {
    match kind {
        AssetKind::Cash => CASH_RAIL,
        AssetKind::Security
        | AssetKind::Fund
        | AssetKind::Commodity
        | AssetKind::Carbon
        | AssetKind::Other => SECURITIES_RAIL,
    }
}

#[derive(Clone)]
struct FacilityPlan {
    facility_id: [u8; 32],
    cap_amount: u64,
    cap_blinding: Scalar,
    asset: AssetDefinition,
}

#[derive(Clone)]
struct SourcePlan {
    handle: [u8; 32],
    amount: u64,
    blinding: Scalar,
    before_commitment: [u8; 32],
}

struct PreparedReservation {
    transition: CreditFacilityTransition,
    relation_proof: CreditFacilityRelationProof,
    authorization: ReservationAuthorization,
    escrow: ReservationEscrow,
    escrow_proof: ReservationEscrowProof,
    typed: TypedInstruction,
    asset_link: AssetLinkProof,
}

struct NoteSourcePlan {
    wallet: Wallet,
    source_note_id: [u8; 32],
    amount: u64,
    blinding: Scalar,
}

struct PreparedNoteReservation {
    transition: CreditFacilityTransition,
    relation_proof: CreditFacilityRelationProof,
    authorization: ReservationAuthorization,
    escrow: NoteReservationEscrow,
    typed: TypedInstruction,
    asset_link: AssetLinkProof,
}

impl PreparedNoteReservation {
    fn receipt_digest(&self) -> Result<[u8; 32], String> {
        self.authorization.statement(&self.transition)
    }
}

fn deterministic_scalar(parts: &[&[u8]]) -> Scalar {
    let mut scalar = Scalar::from_bytes_mod_order(hash(parts));
    if scalar == Scalar::ZERO {
        scalar = Scalar::ONE;
    }
    scalar
}

fn deterministic_wallet(discriminator: &[u8], label: &[u8]) -> Wallet {
    Wallet::from_parts(
        deterministic_scalar(&[b"QOMM:ACCEPTANCE:NOTE-VIEW:v1", discriminator, label]),
        deterministic_scalar(&[b"QOMM:ACCEPTANCE:NOTE-SPEND:v1", discriminator, label]),
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_note_source(
    bridge: &AvalancheNoteBridge<'_, AvalancheRpcClient>,
    client: &AvalancheRpcClient,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    issuer: &Issuer,
    csd_issuer: &CsdIssuerDefinition,
    csd_signer: &dyn Ed25519MessageSigner,
    issued_at: u64,
    asset_id: [u8; 32],
    opening: &AcceptanceOpening,
    discriminator: &[u8],
) -> Result<NoteSourcePlan, String> {
    let wallet = deterministic_wallet(discriminator, b"owner");
    let amount = opening
        .amount
        .checked_add(1)
        .ok_or_else(|| "anonymous reservation source amount overflow".to_string())?;
    let blinding =
        deterministic_scalar(&[b"QOMM:ACCEPTANCE:NOTE-SOURCE-BLINDING:v1", discriminator]);
    let local = NoteLedger::new(issuer.key.clone(), issuer.bounds.amount_bits);
    let note = local.build_note(
        &wallet.address,
        amount,
        issuer.key.commit_u64(amount, &blinding),
        &blinding,
        &mut OsRng,
    );
    let output = NoteOutput::from_note(&note, asset_id, ZERO)?;
    let mut issuance = NoteIssuance {
        operation_id: hash(&[b"QOMM:ACCEPTANCE:NOTE-SOURCE-OPERATION:v1", discriminator]),
        issuance_nonce: hash(&[b"QOMM:ACCEPTANCE:NOTE-SOURCE-NONCE:v1", discriminator]),
        issuer_id: csd_issuer.issuer_id,
        issued_at,
        output,
        proof_digest: hash(&[
            b"QOMM:ACCEPTANCE:CSD-ISSUANCE-EVIDENCE:v1",
            discriminator,
            &asset_id,
        ]),
        issuer_signature: Signature::from_bytes(&[0_u8; 64]),
    };
    issuance.issuer_signature = csd_signer.sign_message(&issuance.issuer_message()?)?;
    issuance.verify_issuer(csd_issuer, issued_at)?;
    let approval = approve_root(
        client.state_root()?,
        authorizer,
        keys,
        issuance.statement()?,
    )?;
    bridge.issue_note(&issuance, &approval)?;

    // A real two-member anonymity set is present before the wallet constructs
    // its proof. The decoy is issued to a distinct address and cannot be
    // opened with the reservation owner's view/spend keys.
    let decoy_wallet = deterministic_wallet(discriminator, b"decoy");
    let decoy_amount = amount.saturating_add(1);
    let decoy_blinding =
        deterministic_scalar(&[b"QOMM:ACCEPTANCE:NOTE-DECOY-BLINDING:v1", discriminator]);
    let decoy = local.build_note(
        &decoy_wallet.address,
        decoy_amount,
        issuer.key.commit_u64(decoy_amount, &decoy_blinding),
        &decoy_blinding,
        &mut OsRng,
    );
    let mut decoy_issuance = NoteIssuance {
        operation_id: hash(&[b"QOMM:ACCEPTANCE:NOTE-DECOY-OPERATION:v1", discriminator]),
        issuance_nonce: hash(&[b"QOMM:ACCEPTANCE:NOTE-DECOY-NONCE:v1", discriminator]),
        issuer_id: csd_issuer.issuer_id,
        issued_at,
        output: NoteOutput::from_note(&decoy, asset_id, ZERO)?,
        proof_digest: hash(&[
            b"QOMM:ACCEPTANCE:CSD-DECOY-EVIDENCE:v1",
            discriminator,
            &asset_id,
        ]),
        issuer_signature: Signature::from_bytes(&[0_u8; 64]),
    };
    decoy_issuance.issuer_signature = csd_signer.sign_message(&decoy_issuance.issuer_message()?)?;
    decoy_issuance.verify_issuer(csd_issuer, issued_at)?;
    let approval = approve_root(
        client.state_root()?,
        authorizer,
        keys,
        decoy_issuance.statement()?,
    )?;
    bridge.issue_note(&decoy_issuance, &approval)?;
    Ok(NoteSourcePlan {
        wallet,
        source_note_id: issuance.output.note_id,
        amount,
        blinding,
    })
}

impl PreparedReservation {
    fn receipt_digest(&self) -> Result<[u8; 32], String> {
        self.authorization.statement(&self.transition)
    }
}

fn register_asset(
    facility: &DefmiFacility,
    bridge: Option<&FacilityAvalancheBridge<'_, AvalancheRpcClient>>,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    asset_id: [u8; 32],
    code: &str,
    kind: AssetKind,
) -> Result<AssetDefinition, String> {
    let asset = AssetDefinition {
        asset_id,
        code: code.into(),
        kind,
        decimals: 0,
        terms_digest: hash(&[b"QOMM:ACCEPTANCE:ASSET-TERMS:v1", &asset_id]),
    };
    let approval = approve(facility, authorizer, keys, asset.statement()?)?;
    if let Some(bridge) = bridge {
        bridge.register_asset(&asset, &approval)?;
    } else {
        facility.register_asset(&asset, &approval)?;
    }
    Ok(asset)
}

struct SourceAccountRequest<'a> {
    owner_handle: [u8; 32],
    asset: &'a AssetDefinition,
    opening: &'a AcceptanceOpening,
    discriminator: &'a [u8],
}

fn open_source_account(
    facility: &DefmiFacility,
    bridge: Option<&FacilityAvalancheBridge<'_, AvalancheRpcClient>>,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    request: SourceAccountRequest<'_>,
) -> Result<SourcePlan, String> {
    let SourceAccountRequest {
        owner_handle,
        asset,
        opening,
        discriminator,
    } = request;
    let point = CompressedRistretto(owner_handle)
        .decompress()
        .ok_or_else(|| "reservation owner handle is not canonical".to_string())?;
    let handle: [u8; 32] = account_of(&point, rail_for(asset.kind))
        .try_into()
        .map_err(|_| "derived source account is not 32 bytes".to_string())?;
    let extra_blinding = Scalar::from(
        u64::from_be_bytes(
            hash(&[b"QOMM:ACCEPTANCE:SOURCE-EXTRA:v1", discriminator])[..8]
                .try_into()
                .expect("eight bytes"),
        )
        .max(1),
    );
    let amount = opening
        .amount
        .checked_add(1)
        .ok_or_else(|| "reservation source amount overflow".to_string())?;
    let blinding = opening.blinding + extra_blinding;
    let before = Pedersen::new(b"qomm:defmi:v1").commit_u64(amount, &blinding);
    let account = AccountOpening {
        handle,
        asset_id: asset.asset_id,
        commitment: before.compress().to_bytes(),
        issuance_nonce: hash(&[b"QOMM:ACCEPTANCE:SOURCE-ISSUANCE:v1", discriminator]),
    };
    let approval = approve(facility, authorizer, keys, account.statement()?)?;
    if let Some(bridge) = bridge {
        bridge.open_account(&account, &approval)?;
    } else {
        facility.open_account(&account, &approval)?;
    }
    Ok(SourcePlan {
        handle,
        amount,
        blinding,
        before_commitment: account.commitment,
    })
}

fn ensure_destination_account(
    facility: &DefmiFacility,
    bridge: Option<&FacilityAvalancheBridge<'_, AvalancheRpcClient>>,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    owner_handle: [u8; 32],
    asset: &AssetDefinition,
) -> Result<(), String> {
    let point = CompressedRistretto(owner_handle)
        .decompress()
        .ok_or_else(|| "destination owner handle is not canonical".to_string())?;
    let handle: [u8; 32] = account_of(&point, rail_for(asset.kind))
        .try_into()
        .map_err(|_| "derived destination account is not 32 bytes".to_string())?;
    if facility.account(&handle)?.is_some() {
        return Ok(());
    }
    let blinding = Scalar::from(
        u64::from_be_bytes(
            hash(&[
                b"QOMM:ACCEPTANCE:DESTINATION-BLINDING:v1",
                &owner_handle,
                &asset.asset_id,
            ])[..8]
                .try_into()
                .expect("eight bytes"),
        )
        .max(1),
    );
    let opening = AccountOpening {
        handle,
        asset_id: asset.asset_id,
        commitment: Pedersen::new(b"qomm:defmi:v1")
            .commit_u64(0, &blinding)
            .compress()
            .to_bytes(),
        issuance_nonce: hash(&[
            b"QOMM:ACCEPTANCE:DESTINATION-ISSUANCE:v1",
            &owner_handle,
            &asset.asset_id,
        ]),
    };
    let approval = approve(facility, authorizer, keys, opening.statement()?)?;
    if let Some(bridge) = bridge {
        bridge.open_account(&opening, &approval).map(|_| ())
    } else {
        facility.open_account(&opening, &approval)
    }
}

#[derive(Clone)]
struct ReservationSpec {
    role: ReservationRole,
    entity_commitment: [u8; 32],
    direction: Direction,
    owner_handle: RistrettoPoint,
    maker_handle: RistrettoPoint,
    taker_handle: RistrettoPoint,
    reserve_id: [u8; 32],
    authorization_digest: [u8; 32],
    mandate_digest: [u8; 32],
    policy_version: u64,
    rfq_nullifier: [u8; 32],
    deadline: u64,
    admission: Option<(OrderedAdmission, [u8; 32])>,
}

#[allow(clippy::too_many_arguments)]
fn prepare_reservation(
    before_state_root: [u8; 32],
    issuer: &Issuer,
    signer: &mut StdioFrostCluster,
    mandate: ReserveMandateRef<'_>,
    venue_id: [u8; 32],
    defmi_id: [u8; 32],
    plan: &FacilityPlan,
    source: &SourcePlan,
    opening: &AcceptanceOpening,
    spec: ReservationSpec,
) -> Result<PreparedReservation, String> {
    if opening.amount > plan.cap_amount {
        return Err("reservation amount exceeds its facility cap".into());
    }
    let after_available = plan.cap_amount - opening.amount;
    let after_available_blinding = plan.cap_blinding - opening.blinding;
    let mut transition = CreditFacilityTransition {
        operation_id: hash(&[
            b"QOMM:ACCEPTANCE:HOLD-OPERATION:v1",
            &spec.reserve_id,
            &[spec.role as u8],
        ]),
        facility_id: plan.facility_id,
        hold_id: spec.reserve_id,
        kind: CreditTransitionKind::Hold,
        query_commitment: spec.authorization_digest,
        amount_commitment: credit_commit(opening.amount, &opening.blinding),
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: credit_commit(plan.cap_amount, &plan.cap_blinding),
        after_available_commitment: credit_commit(after_available, &after_available_blinding),
        before_held_commitment: ZERO,
        after_held_commitment: credit_commit(opening.amount, &opening.blinding),
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: 0,
        expires_at: spec.deadline,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let relation_proof = CreditFacilityRelationProof::prove(
        &mut transition,
        [after_available, opening.amount, 0, opening.amount],
        [
            after_available_blinding,
            opening.blinding,
            Scalar::ZERO,
            opening.blinding,
        ],
        [0, 0],
        [Scalar::ZERO, Scalar::ZERO],
        &mut OsRng,
    )?;
    if transition.amount_commitment
        != Pedersen::new(b"qomm:defmi:v1")
            .commit_u64(opening.amount, &opening.blinding)
            .compress()
            .to_bytes()
    {
        return Err("credit and zkPI commitments use incompatible generators".into());
    }

    let reserve_handle = reserve_handle_for(&plan.facility_id);
    let nonce = hash(&[b"QOMM:ACCEPTANCE:RESERVE-ZKPI-NONCE:v1", &spec.reserve_id]);
    let quote_key = u64::from_be_bytes(
        hash(&[b"QOMM:ACCEPTANCE:RESERVE-QUOTE-KEY:v1", &spec.reserve_id])[..8]
            .try_into()
            .expect("eight bytes"),
    )
    .max(1);
    let (payment_digest, payment_openings, partial) = issuer
        .build_for_asset_id_with_openings(
            opening.amount,
            1,
            plan.asset.asset_id,
            spec.owner_handle,
            reserve_handle,
            spec.deadline,
            nonce,
            quote_key,
            Openings {
                amount: opening.blinding,
                price: Scalar::random(&mut OsRng),
                asset: Scalar::random(&mut OsRng),
            },
            &mut OsRng,
        )
        .map_err(|error| error.to_string())?;
    if partial.digest().as_slice() != payment_digest.as_slice() {
        return Err("reserve issuer returned a mismatched payment digest".into());
    }
    let payment_signature = signer.sign_reserve_payment(&partial, mandate)?;
    let payment = partial.sealed(payment_signature);
    let (maker_reservation_id, taker_reservation_id) = match spec.role {
        ReservationRole::Maker => (spec.reserve_id, ZERO),
        ReservationRole::Taker => (ZERO, spec.reserve_id),
    };
    let (
        admission_ticket_id,
        admission_slot,
        admission_receipt_digest,
        admission_epoch,
        admission_sequence,
        admission_batch_id,
    ) = match &spec.admission {
        Some((ordered, batch_id)) => (
            ordered.ticket_id,
            ordered.slot,
            ordered.certified_digest()?,
            ordered.epoch,
            ordered.sequence,
            *batch_id,
        ),
        None => (ZERO, 0, ZERO, 0, 0, ZERO),
    };
    let context = ExecutionContext {
        operation: OperationKind::Reserve,
        scope: match spec.role {
            ReservationRole::Maker => AuthorizationScope::Maker,
            ReservationRole::Taker => AuthorizationScope::Taker,
        },
        direction: trade_direction(spec.direction),
        venue_id,
        defmi_id,
        maker_handle: spec.maker_handle,
        taker_handle: spec.taker_handle,
        reserve_handle,
        maker_reservation_id,
        maker_reservation_sequence: 0,
        taker_reservation_id,
        taker_reservation_sequence: 0,
        rfq_nullifier: spec.rfq_nullifier,
        taker_mandate_digest: if spec.role == ReservationRole::Taker {
            spec.mandate_digest
        } else {
            ZERO
        },
        maker_policy_digest: if spec.role == ReservationRole::Maker {
            spec.authorization_digest
        } else {
            ZERO
        },
        maker_mandate_digest: if spec.role == ReservationRole::Maker {
            spec.mandate_digest
        } else {
            ZERO
        },
        maker_reserve_receipt_digest: ZERO,
        taker_reserve_receipt_digest: ZERO,
        quote_proof_digest: ZERO,
        market_statement_digest: ZERO,
        before_state_root,
    };
    let typed = TypedInstruction {
        pq_authorization: None,
        authorization: signer.sign_reserve_context(&payment, &context, mandate)?,
        payment,
        context,
    };
    let asset_link = prove_asset_link(
        &issuer.key,
        plan.asset.asset_id,
        &typed.payment.asset_commitment,
        &payment_openings.asset,
        &mut OsRng,
    )?;
    let source_before = CompressedRistretto(source.before_commitment)
        .decompress()
        .ok_or_else(|| "source account commitment is not canonical".to_string())?;
    let mut ledger = Ledger::new(issuer.key.clone(), issuer.bounds.amount_bits);
    ledger.open(&source.handle, source_before);
    let (transfer, _) = ledger
        .build_transfer_with_amount_blinding(
            source.amount,
            &source.blinding,
            opening.amount,
            &opening.blinding,
            &escrow_transfer_context(&spec.reserve_id),
            None,
            &Scalar::ZERO,
            true,
        )
        .map_err(|error| error.to_string())?;
    let escrow_proof = ReservationEscrowProof { transfer };
    let escrow_handle: [u8; 32] = account_of(&reserve_handle, rail_for(plan.asset.kind))
        .try_into()
        .map_err(|_| "derived escrow account is not 32 bytes".to_string())?;
    let escrow = ReservationEscrow {
        source_handle: source.handle,
        escrow_handle,
        asset_id: plan.asset.asset_id,
        amount_commitment: transition.amount_commitment,
        source_before_commitment: source.before_commitment,
        source_after_commitment: escrow_proof
            .transfer
            .remainder_commitment
            .compress()
            .to_bytes(),
        source_before_sequence: 0,
        proof_digest: escrow_proof.digest(),
    };
    let authorization = ReservationAuthorization {
        role: spec.role,
        entity_commitment: spec.entity_commitment,
        asset_id: plan.asset.asset_id,
        direction: spec.direction as u8,
        authorization_digest: spec.authorization_digest,
        mandate_digest: spec.mandate_digest,
        typed_reserve_digest: Sha256::digest(typed_wire::encode(&typed)).into(),
        reserve_nullifier: typed.payment.nullifier(),
        asset_link_proof_digest: asset_link
            .digest(&plan.asset.asset_id, &typed.payment.asset_commitment),
        limit_price_commitment: mandate.limit_price_commitment(),
        escrow_digest: escrow.statement()?,
        rfq_nullifier: spec.rfq_nullifier,
        policy_version: spec.policy_version,
        admission_ticket_id,
        admission_slot,
        admission_receipt_digest,
        admission_epoch,
        admission_sequence,
        admission_batch_id,
    };
    Ok(PreparedReservation {
        transition,
        relation_proof,
        authorization,
        escrow,
        escrow_proof,
        typed,
        asset_link,
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_note_reservation(
    bridge: &AvalancheNoteBridge<'_, AvalancheRpcClient>,
    issuer: &Issuer,
    signer: &mut StdioFrostCluster,
    mandate: ReserveMandateRef<'_>,
    venue_id: [u8; 32],
    defmi_id: [u8; 32],
    plan: &FacilityPlan,
    source: &NoteSourcePlan,
    opening: &AcceptanceOpening,
    spec: ReservationSpec,
) -> Result<PreparedNoteReservation, String> {
    let (pool_root, ledger, outputs) = bridge.note_ledger(
        plan.asset.asset_id,
        issuer.key.clone(),
        issuer.bounds.amount_bits,
        16_384,
    )?;
    let source_index = outputs
        .iter()
        .position(|output| output.note_id == source.source_note_id)
        .ok_or_else(|| "owner's issued source note is absent from Avalanche".to_string())?;
    let source_opening = ledger
        .scan(&source.wallet, &issuer.key)
        .into_iter()
        .find_map(|(index, opening)| (index == source_index).then_some(opening))
        .ok_or_else(|| "owner cannot open its canonical source note".to_string())?;
    if source_opening.value != source.amount || source_opening.blinding != source.blinding {
        return Err("canonical source note differs from its private issuance opening".into());
    }
    let decoy_index = outputs
        .iter()
        .enumerate()
        .find_map(|(index, output)| {
            (index != source_index && output.lock_id == ZERO).then_some(index)
        })
        .ok_or_else(|| "anonymous reservation has no canonical decoy note".to_string())?;
    let ring = if source.source_note_id < outputs[decoy_index].note_id {
        vec![source_index, decoy_index]
    } else {
        vec![decoy_index, source_index]
    };
    let pseudo_source = SourcePlan {
        handle: hash(&[
            b"QOMM:ACCEPTANCE:NOTE-PSEUDO-SOURCE:v1",
            &source.source_note_id,
        ]),
        amount: source.amount,
        blinding: source.blinding,
        before_commitment: issuer
            .key
            .commit_u64(source.amount, &source.blinding)
            .compress()
            .to_bytes(),
    };
    let mut prepared = prepare_reservation(
        pool_root,
        issuer,
        signer,
        mandate,
        venue_id,
        defmi_id,
        plan,
        &pseudo_source,
        opening,
        spec.clone(),
    )?;

    let covenant_wallet = deterministic_wallet(&spec.reserve_id, b"covenant");
    let change = source
        .amount
        .checked_sub(opening.amount)
        .ok_or_else(|| "anonymous source note is smaller than its reservation".to_string())?;
    let change_blinding =
        deterministic_scalar(&[b"QOMM:ACCEPTANCE:NOTE-CHANGE-BLINDING:v1", &spec.reserve_id]);
    let outputs_requested = vec![
        (covenant_wallet.address, opening.amount),
        (source.wallet.address, change),
    ];
    let spend_context = [
        b"QOMM:ACCEPTANCE:NOTE-RESERVATION-SPEND:v1".as_slice(),
        &spec.reserve_id,
    ]
    .concat();
    let spend = ledger
        .build_spend_constrained_with_blindings(
            &ring,
            source_index,
            &source_opening,
            &issuer.key.g,
            &Scalar::ZERO,
            &outputs_requested,
            &[opening.blinding, change_blinding],
            &[true, true],
            &spend_context,
            &mut OsRng,
        )
        .map_err(str::to_string)?;
    let ring_locks = vec![ZERO; ring.len()];
    let output_locks = [spec.reserve_id, ZERO];
    let delegation_digest = hash(&[
        b"QOMM:ACCEPTANCE:DELEGATED-RESERVATION:v1",
        &spec.reserve_id,
        &spec.mandate_digest,
        &venue_id,
        &defmi_id,
        &plan.asset.asset_id,
        &[spec.direction as u8],
        &spec.deadline.to_be_bytes(),
    ]);
    let escrow = NoteReservationEscrow::from_verified(
        &ledger,
        &ring,
        &spend.proof,
        &spend.notes,
        plan.asset.asset_id,
        &ring_locks,
        &output_locks,
        &prepared.transition,
        delegation_digest,
        &spend_context,
        &mut OsRng,
    )?;
    prepared.authorization.escrow_digest =
        escrow.statement(&prepared.transition, &prepared.authorization)?;
    Ok(PreparedNoteReservation {
        transition: prepared.transition,
        relation_proof: prepared.relation_proof,
        authorization: prepared.authorization,
        escrow,
        typed: prepared.typed,
        asset_link: prepared.asset_link,
    })
}

type FacilityKey = ([u8; 32], [u8; 32]);
type OwnerKey = (ReservationParty, u16, u8);

fn verify_opening(amount_commitment: [u8; 32], opening: &AcceptanceOpening) -> Result<(), String> {
    let expected = Pedersen::new(b"qomm:defmi:v1")
        .commit_u64(opening.amount, &opening.blinding)
        .compress()
        .to_bytes();
    if expected != amount_commitment || opening.amount == 0 {
        return Err("pre-trade opening does not match the signed maximum".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_authority_notes(
    authority: &PretradeAuthorityBundle,
    authority_digest: [u8; 32],
    certified: &[CertifiedAdmissionLane],
    client: &AvalancheRpcClient,
    authorizer_domain: &str,
    proof_party_bin: &Path,
    proof_root: &Path,
    csd_signer: &dyn Ed25519MessageSigner,
) -> Result<(PretradeAcknowledgement, serde_json::Value), String> {
    let now = authority.created_at;
    let admission = authority.admission.as_ref().ok_or_else(|| {
        "pre-trade authority omits the certified admission population".to_string()
    })?;
    let governance = governance_keys();
    let authorizer = authorizer(&governance, authorizer_domain)?;
    let bridge = AvalancheNoteBridge::new(&authorizer, client);
    let signing_receipts = receipt_key();
    let approve_chain = |statement: [u8; 32]| {
        approve_root(client.state_root()?, &authorizer, &governance, statement)
    };

    let traded_asset = AssetDefinition {
        asset_id: authority.traded_asset_id,
        code: "QOMM-LIVE-PRODUCT".into(),
        kind: AssetKind::Security,
        decimals: 0,
        terms_digest: hash(&[
            b"QOMM:ACCEPTANCE:ASSET-TERMS:v1",
            &authority.traded_asset_id,
        ]),
    };
    bridge.register_asset(&traded_asset, &approve_chain(traded_asset.statement()?)?)?;
    let cash_asset = AssetDefinition {
        asset_id: authority.cash_asset_id,
        code: "QOMM-LIVE-CASH".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: hash(&[b"QOMM:ACCEPTANCE:ASSET-TERMS:v1", &authority.cash_asset_id]),
    };
    bridge.register_asset(&cash_asset, &approve_chain(cash_asset.statement()?)?)?;
    let assets = BTreeMap::from([
        (traded_asset.asset_id, traded_asset.clone()),
        (cash_asset.asset_id, cash_asset.clone()),
    ]);

    // DeFMI contains a native, JASDEC-like issuer registry. Asset registration
    // defines the rail; this separately authorizes who may create canonical
    // units on that rail. Every mint still needs both this CSD signature and
    // the independent 3-of-7 DeFMI governance approval.
    let mut permitted_asset_ids = vec![traded_asset.asset_id, cash_asset.asset_id];
    permitted_asset_ids.sort_unstable();
    let csd_issuer = CsdIssuerDefinition {
        issuer_id: hash(&[b"QOMM:ACCEPTANCE:CSD-ISSUER:v1", &authority.defmi_id]),
        code: "DEFMI-JP-CSD".into(),
        jurisdiction: "JP".into(),
        operator_entity_commitment: hash(&[
            b"QOMM:ACCEPTANCE:CSD-OPERATOR:v1",
            &authority.defmi_id,
        ]),
        public_key: csd_signer.verifying_key().to_bytes(),
        permitted_asset_ids,
        policy_digest: hash(&[b"QOMM:ACCEPTANCE:CSD-POLICY:v1", &authority.defmi_id]),
        valid_from: now.saturating_sub(1).max(1),
        valid_until: now.saturating_add(31_536_000),
    };
    bridge.register_csd_issuer(&csd_issuer, &approve_chain(csd_issuer.statement()?)?)?;
    let canonical_csd = bridge.csd_issuer(csd_issuer.issuer_id)?;
    if canonical_csd.definition != csd_issuer || canonical_csd.status != "active" {
        return Err("registered CSD issuer differs from Avalanche canonical state".into());
    }

    let guarantor_kinds = [
        GuarantorKind::CentralCounterparty,
        GuarantorKind::Bank,
        GuarantorKind::SelfGuaranteed,
    ];
    let mut guarantors = Vec::new();
    for (index, kind) in guarantor_kinds.into_iter().enumerate() {
        let seed: [u8; 32] = Sha256::new()
            .chain_update(b"QOMM:ACCEPTANCE:GUARANTOR-KEY:v1")
            .chain_update((index as u64).to_be_bytes())
            .finalize()
            .into();
        let key = SigningKey::from_bytes(&seed);
        let definition = GuarantorDefinition {
            guarantor_id: hash(&[
                b"QOMM:ACCEPTANCE:GUARANTOR:v1",
                &(index as u64).to_be_bytes(),
            ]),
            kind,
            name: match kind {
                GuarantorKind::CentralBank => "Acceptance central bank",
                GuarantorKind::CentralCounterparty => "Acceptance CCP",
                GuarantorKind::Bank => "Acceptance bank",
                GuarantorKind::SelfGuaranteed => "Acceptance self-guarantee",
                GuarantorKind::CreditProvider => "Acceptance credit provider",
            }
            .into(),
            public_key: key.verifying_key().to_bytes(),
            risk_policy_digest: hash(&[
                b"QOMM:ACCEPTANCE:RISK-POLICY:v1",
                &(index as u64).to_be_bytes(),
            ]),
        };
        bridge.register_guarantor(&definition, &approve_chain(definition.statement()?)?)?;
        guarantors.push((definition, key));
    }

    let mut group_openings = BTreeMap::<FacilityKey, AcceptanceOpening>::new();
    for maker in &authority.makers {
        let key = (maker.mandate.entity_commitment, maker.mandate.asset_id);
        match group_openings.get(&key) {
            Some(prior)
                if prior.amount != maker.acceptance_opening.amount
                    || prior.blinding != maker.acceptance_opening.blinding =>
            {
                return Err("one legal-entity facility has conflicting Maker maxima".into());
            }
            Some(_) => {}
            None => {
                group_openings.insert(key, maker.acceptance_opening.clone());
            }
        }
    }
    for taker in &authority.takers {
        let key = (
            taker.mandate.entity_commitment,
            taker.mandate.reserve_asset_id,
        );
        match group_openings.get(&key) {
            Some(prior)
                if prior.amount != taker.acceptance_opening.amount
                    || prior.blinding != taker.acceptance_opening.blinding =>
            {
                return Err("one legal-entity facility has conflicting Taker maxima".into());
            }
            Some(_) => {}
            None => {
                group_openings.insert(key, taker.acceptance_opening.clone());
            }
        }
    }
    let mut facility_plans = BTreeMap::<FacilityKey, FacilityPlan>::new();
    for (index, (key, opening)) in group_openings.iter().enumerate() {
        let asset = assets
            .get(&key.1)
            .ok_or_else(|| "mandate names an unregistered asset".to_string())?
            .clone();
        let (guarantor, guarantor_key) = &guarantors[index % guarantors.len()];
        let facility_id = hash(&[
            b"QOMM:ACCEPTANCE:FACILITY:v1",
            &key.0,
            &key.1,
            &guarantor.guarantor_id,
        ]);
        let cap_commitment = credit_commit(opening.amount, &opening.blinding);
        let collateral_blinding = opening.blinding + Scalar::ONE;
        let mut grant = CreditFacilityGrant {
            operation_id: hash(&[b"QOMM:ACCEPTANCE:FACILITY-GRANT:v1", &facility_id]),
            facility_id,
            guarantor_id: guarantor.guarantor_id,
            beneficiary_commitment: key.0,
            rail_asset_id: key.1,
            cap_commitment,
            available_commitment: cap_commitment,
            held_commitment: ZERO,
            outstanding_commitment: ZERO,
            collateral_commitment: credit_commit(
                opening.amount.saturating_add(1),
                &collateral_blinding,
            ),
            risk_policy_digest: guarantor.risk_policy_digest,
            relation_proof_digest: hash(&[
                b"QOMM:ACCEPTANCE:FACILITY-GRANT-PROOF:v1",
                &facility_id,
            ]),
            valid_from: now.saturating_sub(1).max(1),
            valid_until: now.saturating_add(7_200),
            nonce: hash(&[b"QOMM:ACCEPTANCE:FACILITY-GRANT-NONCE:v1", &facility_id]),
            guarantor_signature: Signature::from_bytes(&[0_u8; 64]),
        };
        grant.guarantor_signature = guarantor_key.sign(&grant.guarantor_message()?);
        bridge.grant_credit_facility(&grant, &approve_chain(grant.statement()?)?)?;
        facility_plans.insert(
            *key,
            FacilityPlan {
                facility_id,
                cap_amount: opening.amount,
                cap_blinding: opening.blinding,
                asset,
            },
        );
    }

    let issuer = Issuer::new(Pedersen::new(b"qomm:defmi:v1"), Bounds::default());
    let mut sources = BTreeMap::<OwnerKey, NoteSourcePlan>::new();
    for maker in &authority.makers {
        let discriminator = [
            b"maker".as_slice(),
            &maker.maker_index.to_be_bytes(),
            &[maker.mandate.direction as u8],
        ]
        .concat();
        sources.insert(
            (
                ReservationParty::Maker,
                maker.maker_index,
                maker.mandate.direction as u8,
            ),
            issue_note_source(
                &bridge,
                client,
                &authorizer,
                &governance,
                &issuer,
                &csd_issuer,
                csd_signer,
                now,
                maker.mandate.asset_id,
                &maker.acceptance_opening,
                &discriminator,
            )?,
        );
    }
    for taker in &authority.takers {
        let discriminator = [
            b"taker".as_slice(),
            &taker.client_index.to_be_bytes(),
            &[taker.mandate.direction as u8],
        ]
        .concat();
        sources.insert(
            (
                ReservationParty::Taker,
                taker.client_index,
                taker.mandate.direction as u8,
            ),
            issue_note_source(
                &bridge,
                client,
                &authorizer,
                &governance,
                &issuer,
                &csd_issuer,
                csd_signer,
                now,
                taker.mandate.reserve_asset_id,
                &taker.acceptance_opening,
                &discriminator,
            )?,
        );
    }

    let committee = AdmissionCommitteePlan {
        operation_id: hash(&[b"QOMM:ACCEPTANCE:ADMISSION-COMMITTEE:v1", &authority_digest]),
        venue_id: authority.venue_id,
        epoch: admission.epoch,
        node_keys: admission.node_keys.clone(),
        valid_from: now.saturating_sub(1).max(1),
        valid_until: now.saturating_add(3_600),
    };
    if authority.settlement_verifier.epoch != admission.epoch {
        return Err("settlement verifier epoch differs from admission".into());
    }
    let settlement_verifier = SettlementVerifierConfig {
        venue_id: authority.venue_id,
        defmi_id: authority.defmi_id,
        epoch: authority.settlement_verifier.epoch,
        quote_registry_digest: authority.settlement_verifier.quote_registry_digest,
        quote_eligibility_bits: authority.settlement_verifier.quote_eligibility_bits,
        quote_span_bits: authority.settlement_verifier.quote_span_bits,
        amount_bits: authority.settlement_verifier.amount_bits,
        price_bits: authority.settlement_verifier.price_bits,
        max_horizon: authority.settlement_verifier.max_horizon,
        frost_public_package: authority
            .settlement_verifier
            .frost_public
            .serialize()
            .map_err(|_| "settlement verifier FROST package serialization failed")?,
        pq_committee: authority.settlement_verifier.pq_committee.clone(),
        valid_from: authority.settlement_verifier.valid_from,
        valid_until: authority.settlement_verifier.valid_until,
    };
    bridge.register_settlement_verifier(
        &settlement_verifier,
        &approve_chain(settlement_verifier.statement()?)?,
    )?;
    bridge.register_admission_committee(&committee, &approve_chain(committee.statement()?)?)?;
    let batch_id = hash(&[b"QOMM:ACCEPTANCE:ADMISSION-BATCH:v1", &authority_digest]);
    let batch = AdmissionBatchPlan {
        operation_id: hash(&[
            b"QOMM:ACCEPTANCE:ADMISSION-BATCH-OPERATION:v1",
            &authority_digest,
        ]),
        batch_id,
        venue_id: authority.venue_id,
        epoch: admission.epoch,
        slot: certified[0].slot,
        batch_digest: certified[0].cluster_digest,
        order_digest: certified[0].order_digest,
        first_sequence: certified[0].sequence,
        admission_digests: certified
            .iter()
            .map(|lane| lane.digest(authority.venue_id, admission.epoch))
            .collect::<Result<Vec<_>, _>>()?,
        expires_at: authority
            .takers
            .iter()
            .map(|taker| taker.mandate.deadline)
            .min()
            .ok_or_else(|| "pre-trade authority has no Taker deadline".to_string())?,
    };
    bridge.register_admission_batch(
        &batch,
        &admission.lanes,
        &approve_chain(batch.statement()?)?,
    )?;

    let reserve_frost_session = hash(&[
        b"QOMM:RESERVE:FROST:DKG-SESSION:v1",
        &authority_digest,
        authorizer_domain.as_bytes(),
        b":notes",
    ]);
    let mut reserve_signers = StdioFrostCluster::start(
        proof_party_bin,
        proof_root,
        reserve_frost_session,
        7,
        vec![1, 4, 7],
    )?;
    let public = reserve_signers.public().clone();
    let venue = Venue::new(issuer.key.clone(), &issuer.bounds, public.clone());
    let mut bindings = Vec::new();

    for maker in &authority.makers {
        let key = (maker.mandate.entity_commitment, maker.mandate.asset_id);
        let plan = facility_plans
            .get(&key)
            .ok_or_else(|| "Maker facility was not provisioned".to_string())?;
        let source = sources
            .get(&(
                ReservationParty::Maker,
                maker.maker_index,
                maker.mandate.direction as u8,
            ))
            .ok_or_else(|| "Maker source note was not provisioned".to_string())?;
        let maker_handle = CompressedRistretto(maker.mandate.maker_handle)
            .decompress()
            .ok_or_else(|| "Maker handle is not canonical".to_string())?;
        let taker_placeholder = RistrettoPoint::mul_base(&Scalar::from(
            50_000_u64
                + u64::from(maker.maker_index) * 2
                + u64::from(maker.mandate.direction as u8),
        ));
        let mandate_digest = maker.mandate.digest()?;
        let prepared = prepare_note_reservation(
            &bridge,
            &issuer,
            &mut reserve_signers,
            ReserveMandateRef::Maker(&maker.mandate),
            authority.venue_id,
            authority.defmi_id,
            plan,
            source,
            &maker.acceptance_opening,
            ReservationSpec {
                role: ReservationRole::Maker,
                entity_commitment: maker.mandate.entity_commitment,
                direction: maker.mandate.direction,
                owner_handle: maker_handle,
                maker_handle,
                taker_handle: taker_placeholder,
                reserve_id: maker.mandate.reserve_id,
                authorization_digest: maker.mandate.policy_digest,
                mandate_digest,
                policy_version: maker.mandate.policy_version,
                rfq_nullifier: ZERO,
                deadline: maker.mandate.valid_until,
                admission: None,
            },
        )?;
        let identity = IdentityEvidence {
            presentation: &maker.presentation,
            registry: &authority.registry,
            trusted_issuer: &trusted_kyb_issuer(),
            scope: &authority.identity_scope,
            context: &maker.identity_context,
            required_cohort: &authority.required_cohort,
        };
        verify_maker_reservation(
            &prepared.transition,
            &prepared.authorization,
            &prepared.typed,
            &maker.mandate,
            &identity,
            now,
        )?;
        verify_note_reservation(
            &prepared.transition,
            &prepared.relation_proof,
            &prepared.authorization,
            &prepared.escrow,
            &prepared.typed,
            &venue,
            &prepared.asset_link,
            None,
            now,
        )?;
        let receipt_digest = prepared.receipt_digest()?;
        let before = client.state_root()?;
        if prepared.typed.context.before_state_root != before {
            return Err("Maker note reserve proof was built over a stale L1 root".into());
        }
        bridge.reserve_product(
            &prepared.transition,
            &prepared.authorization,
            &prepared.escrow,
            &approve_root(before, &authorizer, &governance, receipt_digest)?,
        )?;
        let canonical = bridge.note_reservation(maker.mandate.reserve_id)?;
        if canonical.delegation_digest != prepared.escrow.delegation_digest
            || canonical.escrow_note_id != prepared.escrow.escrow_note_id
            || canonical.status != "active"
        {
            return Err("Avalanche stored a different Maker reservation covenant".into());
        }
        bindings.push(PretradeReservationBinding {
            party: ReservationParty::Maker,
            owner_index: maker.maker_index,
            direction: maker.mandate.direction,
            owner_handle: maker.mandate.maker_handle,
            facility_id: plan.facility_id,
            reserve_id: maker.mandate.reserve_id,
            mandate_digest,
            policy_digest: maker.mandate.policy_digest,
            amount_commitment: maker.mandate.maximum_amount_commitment,
            reserve_receipt_digest: receipt_digest,
        });
    }

    let mut takers_by_claim = BTreeMap::<[u8; 32], &TakerPretradeAuthority>::new();
    for taker in &authority.takers {
        let digest = taker.mandate.digest()?;
        if takers_by_claim.insert(digest, taker).is_some() {
            return Err("two Taker authorities have the same mandate digest".into());
        }
    }
    let lane_by_claim = certified
        .iter()
        .map(|lane| (lane.claim_digest, lane.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut facility_populations = BTreeMap::<FacilityKey, usize>::new();
    for taker in &authority.takers {
        *facility_populations
            .entry((
                taker.mandate.entity_commitment,
                taker.mandate.reserve_asset_id,
            ))
            .or_default() += 1;
    }
    let ordered_for = |taker: &TakerPretradeAuthority,
                       lane: &CertifiedAdmissionLane|
     -> Result<OrderedAdmission, String> {
        Ok(OrderedAdmission {
            venue_id: authority.venue_id,
            epoch: admission.epoch,
            slot: lane.slot,
            sequence: lane.sequence,
            ticket_id: lane.ticket_id,
            batch_digest: lane.cluster_digest,
            order_digest: lane.order_digest,
            rfq_nullifier: taker.mandate.rfq_nullifier,
            taker_entity_commitment: taker.mandate.entity_commitment,
            taker_mandate_digest: taker.mandate.digest()?,
            expires_at: taker.mandate.deadline,
        })
    };
    let mut prepared_takers = BTreeMap::<u16, PreparedNoteReservation>::new();
    let mut accepted_clients = BTreeSet::new();
    let mut rejected_clients = BTreeSet::new();
    let mut consumed_lanes = 0_u64;
    for lane in certified {
        let admission_digest = lane.digest(authority.venue_id, admission.epoch)?;
        let Some(taker) = takers_by_claim.get(&lane.claim_digest).copied() else {
            let advance = AdmissionSlotAdvance {
                operation_id: hash(&[
                    b"QOMM:ACCEPTANCE:COVER-ADVANCE:v1",
                    &batch_id,
                    &lane.sequence.to_be_bytes(),
                ]),
                batch_id,
                sequence: lane.sequence,
                admission_digest,
            };
            bridge.advance_admission(&advance, &approve_chain(advance.statement()?)?)?;
            consumed_lanes = lane.sequence;
            continue;
        };
        let key = (
            taker.mandate.entity_commitment,
            taker.mandate.reserve_asset_id,
        );
        let population = facility_populations[&key];
        if population > 1
            && !authority
                .takers
                .iter()
                .filter(|candidate| {
                    candidate.mandate.entity_commitment == key.0
                        && candidate.mandate.reserve_asset_id == key.1
                })
                .any(|candidate| prepared_takers.contains_key(&candidate.client_index))
        {
            for candidate in authority.takers.iter().filter(|candidate| {
                candidate.mandate.entity_commitment == key.0
                    && candidate.mandate.reserve_asset_id == key.1
            }) {
                let candidate_lane = lane_by_claim
                    .get(&candidate.mandate.digest()?)
                    .ok_or_else(|| "shared-cap Taker lane is missing".to_string())?;
                let plan = facility_plans
                    .get(&key)
                    .ok_or_else(|| "shared Taker facility was not provisioned".to_string())?;
                let source = sources
                    .get(&(
                        ReservationParty::Taker,
                        candidate.client_index,
                        candidate.mandate.direction as u8,
                    ))
                    .ok_or_else(|| "shared Taker source note was not provisioned".to_string())?;
                let taker_handle = CompressedRistretto(candidate.mandate.taker_handle)
                    .decompress()
                    .ok_or_else(|| "Taker handle is not canonical".to_string())?;
                let maker_placeholder = RistrettoPoint::mul_base(&Scalar::from(
                    60_000_u64 + u64::from(candidate.client_index),
                ));
                let mandate_digest = candidate.mandate.digest()?;
                prepared_takers.insert(
                    candidate.client_index,
                    prepare_note_reservation(
                        &bridge,
                        &issuer,
                        &mut reserve_signers,
                        ReserveMandateRef::Taker(&candidate.mandate),
                        authority.venue_id,
                        authority.defmi_id,
                        plan,
                        source,
                        &candidate.acceptance_opening,
                        ReservationSpec {
                            role: ReservationRole::Taker,
                            entity_commitment: candidate.mandate.entity_commitment,
                            direction: candidate.mandate.direction,
                            owner_handle: taker_handle,
                            maker_handle: maker_placeholder,
                            taker_handle,
                            reserve_id: candidate.mandate.reserve_id,
                            authorization_digest: mandate_digest,
                            mandate_digest,
                            policy_version: 0,
                            rfq_nullifier: candidate.mandate.rfq_nullifier,
                            deadline: candidate.mandate.deadline,
                            admission: Some((ordered_for(candidate, candidate_lane)?, batch_id)),
                        },
                    )?,
                );
            }
        }
        if let std::collections::btree_map::Entry::Vacant(entry) =
            prepared_takers.entry(taker.client_index)
        {
            let plan = facility_plans
                .get(&key)
                .ok_or_else(|| "Taker facility was not provisioned".to_string())?;
            let source = sources
                .get(&(
                    ReservationParty::Taker,
                    taker.client_index,
                    taker.mandate.direction as u8,
                ))
                .ok_or_else(|| "Taker source note was not provisioned".to_string())?;
            let taker_handle = CompressedRistretto(taker.mandate.taker_handle)
                .decompress()
                .ok_or_else(|| "Taker handle is not canonical".to_string())?;
            let maker_placeholder =
                RistrettoPoint::mul_base(&Scalar::from(60_000_u64 + u64::from(taker.client_index)));
            let mandate_digest = taker.mandate.digest()?;
            entry.insert(prepare_note_reservation(
                &bridge,
                &issuer,
                &mut reserve_signers,
                ReserveMandateRef::Taker(&taker.mandate),
                authority.venue_id,
                authority.defmi_id,
                plan,
                source,
                &taker.acceptance_opening,
                ReservationSpec {
                    role: ReservationRole::Taker,
                    entity_commitment: taker.mandate.entity_commitment,
                    direction: taker.mandate.direction,
                    owner_handle: taker_handle,
                    maker_handle: maker_placeholder,
                    taker_handle,
                    reserve_id: taker.mandate.reserve_id,
                    authorization_digest: mandate_digest,
                    mandate_digest,
                    policy_version: 0,
                    rfq_nullifier: taker.mandate.rfq_nullifier,
                    deadline: taker.mandate.deadline,
                    admission: Some((ordered_for(taker, lane)?, batch_id)),
                },
            )?);
        }
        let prepared = prepared_takers
            .remove(&taker.client_index)
            .ok_or_else(|| "Taker note reservation preparation disappeared".to_string())?;
        let ordered = ordered_for(taker, lane)?;
        let identity = IdentityEvidence {
            presentation: &taker.presentation,
            registry: &authority.registry,
            trusted_issuer: &trusted_kyb_issuer(),
            scope: &authority.identity_scope,
            context: &taker.identity_context,
            required_cohort: &authority.required_cohort,
        };
        verify_taker_reservation(
            &prepared.transition,
            &prepared.authorization,
            &prepared.typed,
            &taker.mandate,
            &ordered,
            &identity,
            now,
        )?;
        verify_note_reservation(
            &prepared.transition,
            &prepared.relation_proof,
            &prepared.authorization,
            &prepared.escrow,
            &prepared.typed,
            &venue,
            &prepared.asset_link,
            Some(&ordered),
            now,
        )?;
        let receipt_digest = prepared.receipt_digest()?;
        let before = client.state_root()?;
        let result = bridge.reserve_product(
            &prepared.transition,
            &prepared.authorization,
            &prepared.escrow,
            &approve_root(before, &authorizer, &governance, receipt_digest)?,
        );
        match result {
            Ok(_) => {
                if prepared.typed.context.before_state_root != before {
                    return Err("accepted Taker note reserve used a stale L1 proof root".into());
                }
                let canonical = bridge.note_reservation(taker.mandate.reserve_id)?;
                if canonical.delegation_digest != prepared.escrow.delegation_digest
                    || canonical.status != "active"
                {
                    return Err("Avalanche stored a different Taker reservation covenant".into());
                }
                accepted_clients.insert(taker.client_index);
                bindings.push(PretradeReservationBinding {
                    party: ReservationParty::Taker,
                    owner_index: taker.client_index,
                    direction: taker.mandate.direction,
                    owner_handle: taker.mandate.taker_handle,
                    facility_id: facility_plans[&key].facility_id,
                    reserve_id: taker.mandate.reserve_id,
                    mandate_digest: taker.mandate.digest()?,
                    policy_digest: ZERO,
                    amount_commitment: taker.mandate.maximum_amount_commitment,
                    reserve_receipt_digest: receipt_digest,
                });
                consumed_lanes = lane.sequence;
            }
            Err(error)
                if population > 1
                    && error.contains("Avalanche consensus rejected transaction")
                    && error.contains(
                        "anonymous reservation was proved against stale facility state",
                    ) =>
            {
                if client.state_root()? != before {
                    return Err("rejected shared-cap note RFQ changed authoritative state".into());
                }
                let advance = AdmissionSlotAdvance {
                    operation_id: hash(&[
                        b"QOMM:ACCEPTANCE:CAP-REJECTION-ADVANCE:v1",
                        &batch_id,
                        &lane.sequence.to_be_bytes(),
                    ]),
                    batch_id,
                    sequence: lane.sequence,
                    admission_digest,
                };
                bridge.advance_admission(&advance, &approve_chain(advance.statement()?)?)?;
                consumed_lanes = lane.sequence;
                rejected_clients.insert(taker.client_index);
                eprintln!(
                    "shared-cap anonymous RFQ {} rejected without state leakage: {}",
                    taker.client_index, error
                );
            }
            Err(error) if population > 1 => {
                return Err(format!(
                    "shared-cap anonymous RFQ did not reach the expected final cap rejection: {error}"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "independent Taker note reservation failed: {error}"
                ))
            }
        }
    }
    if consumed_lanes != certified.len() as u64
        || accepted_clients.len() != 2
        || rejected_clients.len() != 1
    {
        return Err(
            "anonymous fixed population or legal-entity cap has an unexpected state".into(),
        );
    }

    let after_state_root = client.state_root()?;
    let acknowledgement = PretradeAcknowledgement {
        authority_digest,
        defmi_id: authority.defmi_id,
        after_state_root,
        bindings,
        signer_public: signing_receipts.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0_u8; 64]),
    }
    .sign(&signing_receipts)?;
    acknowledgement.verify(&signing_receipts.verifying_key())?;
    let reserve_public_digest: [u8; 32] = Sha256::digest(
        public
            .serialize()
            .map_err(|_| "reserve FROST public package cannot be serialized")?,
    )
    .into();
    reserve_signers.close()?;
    let report = json!({
        "version": 2,
        "authoritative_backend": "avalanche_l1_account_free_notes",
        "authorizer_domain": authorizer_domain,
        "authority_digest": hex::encode(authority_digest),
        "after_state_root": hex::encode(after_state_root),
        "admission_population": certified.len(),
        "admission_consumed": consumed_lanes,
        "accepted_taker_clients": accepted_clients,
        "rejected_taker_clients": rejected_clients,
        "maker_reservations": authority.makers.len(),
        "source_accounts_created": 0,
        "destination_accounts_created": 0,
        "pre_quote_owner_signature": true,
        "post_quote_owner_signature_required": false,
        "reservation_covenant": "delegated one-use note",
        "reserve_zkpi_signing": {
            "process_isolated_parties": 7,
            "threshold": 3,
            "central_secret_share_collection": false,
            "public_package_digest": hex::encode(reserve_public_digest),
        },
        "guarantor_kinds": ["ccp", "bank", "self"],
        "external_identity": {
            "provider": authority.identity_provider,
            "evidence_digest": hex::encode(authority.identity_evidence_digest),
            "raw_legal_entity_identifier_disclosed": false,
            "anonymous_scope_nullifier": true,
        },
        "csd_issuer": {
            "issuer_id": hex::encode(csd_issuer.issuer_id),
            "code": csd_issuer.code,
            "jurisdiction": csd_issuer.jurisdiction,
            "status": canonical_csd.status,
            "permitted_asset_count": csd_issuer.permitted_asset_ids.len(),
            "per_note_issuer_signature": true,
            "defmi_quorum_approval": true,
            "signer_backend": "external-command",
            "signer_key_id": csd_signer.key_id(),
            "private_key_loaded_by_defmi": false,
            "hardware_hsm_verified": false,
        },
        "legal_entity_cap_key": "entity_commitment + guarantor_id + rail_asset_id",
        "state_database": null,
    });
    Ok((acknowledgement, report))
}

struct AuthorityProcessing<'a> {
    authority: &'a PretradeAuthorityBundle,
    state_path: &'a Path,
    avalanche_client: Option<&'a AvalancheRpcClient>,
    authorizer_domain: &'a str,
    proof_party_bin: &'a Path,
    proof_root: &'a Path,
    account_free_notes: bool,
    csd_signer: Option<&'a dyn Ed25519MessageSigner>,
}

fn process_authority(
    config: AuthorityProcessing<'_>,
) -> Result<(PretradeAcknowledgement, serde_json::Value), String> {
    let AuthorityProcessing {
        authority,
        state_path,
        avalanche_client,
        authorizer_domain,
        proof_party_bin,
        proof_root,
        account_free_notes,
        csd_signer,
    } = config;
    let authority_digest = authority.digest()?;
    let now = authority.created_at;
    if authority.registry.issuer != trusted_kyb_issuer() {
        return Err("pre-trade registry is not from the governance-pinned KYB issuer".into());
    }
    let admission = authority.admission.as_ref().ok_or_else(|| {
        "pre-trade authority omits the certified admission population".to_string()
    })?;
    let admission_keys = admission
        .node_keys
        .iter()
        .map(|raw| {
            ed25519_dalek::VerifyingKey::from_bytes(raw)
                .map_err(|_| "admission key is malformed".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut certified = admission
        .lanes
        .iter()
        .map(|lane| verify_admission_lane(lane, &admission_keys))
        .collect::<Result<Vec<_>, _>>()?;
    certified.sort_by_key(|lane| lane.sequence);
    if certified
        .iter()
        .enumerate()
        .any(|(index, lane)| lane.sequence != index as u64 + 1 || lane.slot != certified[0].slot)
    {
        return Err("certified admission population is incomplete or spans slots".into());
    }

    for maker in &authority.makers {
        maker.mandate.verify(
            &maker.presentation,
            &authority.registry,
            &trusted_kyb_issuer(),
            &authority.identity_scope,
            &maker.identity_context,
            &authority.required_cohort,
            now,
        )?;
        verify_opening(
            maker.mandate.maximum_amount_commitment,
            &maker.acceptance_opening,
        )?;
    }
    for taker in &authority.takers {
        taker.mandate.verify(
            &taker.presentation,
            &authority.registry,
            &trusted_kyb_issuer(),
            &authority.identity_scope,
            &taker.identity_context,
            &authority.required_cohort,
            now,
        )?;
        verify_opening(
            taker.mandate.maximum_amount_commitment,
            &taker.acceptance_opening,
        )?;
    }

    if account_free_notes {
        let client = avalanche_client.ok_or_else(|| {
            "--account-free-notes requires an authoritative Avalanche endpoint".to_string()
        })?;
        return process_authority_notes(
            authority,
            authority_digest,
            &certified,
            client,
            authorizer_domain,
            proof_party_bin,
            proof_root,
            csd_signer.ok_or_else(|| {
                "account-free note issuance requires an external CSD signer".to_string()
            })?,
        );
    }

    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    let governance = governance_keys();
    let authorizer = authorizer(&governance, authorizer_domain)?;
    let signing_receipts = receipt_key();
    let facility = DefmiFacility::open(state_path, authorizer.clone(), signing_receipts.clone())?;
    let bridge = avalanche_client.map(|client| FacilityAvalancheBridge::new(&facility, client));
    let traded_asset = register_asset(
        &facility,
        bridge.as_ref(),
        &authorizer,
        &governance,
        authority.traded_asset_id,
        "QOMM-LIVE-PRODUCT",
        AssetKind::Security,
    )?;
    let cash_asset = register_asset(
        &facility,
        bridge.as_ref(),
        &authorizer,
        &governance,
        authority.cash_asset_id,
        "QOMM-LIVE-CASH",
        AssetKind::Cash,
    )?;
    let assets = BTreeMap::from([
        (traded_asset.asset_id, traded_asset.clone()),
        (cash_asset.asset_id, cash_asset.clone()),
    ]);

    let guarantor_kinds = [
        GuarantorKind::CentralCounterparty,
        GuarantorKind::Bank,
        GuarantorKind::SelfGuaranteed,
    ];
    let mut guarantors = Vec::new();
    for (index, kind) in guarantor_kinds.into_iter().enumerate() {
        let seed: [u8; 32] = Sha256::new()
            .chain_update(b"QOMM:ACCEPTANCE:GUARANTOR-KEY:v1")
            .chain_update((index as u64).to_be_bytes())
            .finalize()
            .into();
        let key = SigningKey::from_bytes(&seed);
        let definition = GuarantorDefinition {
            guarantor_id: hash(&[
                b"QOMM:ACCEPTANCE:GUARANTOR:v1",
                &(index as u64).to_be_bytes(),
            ]),
            kind,
            name: match kind {
                GuarantorKind::CentralBank => "Acceptance central bank",
                GuarantorKind::CentralCounterparty => "Acceptance CCP",
                GuarantorKind::Bank => "Acceptance bank",
                GuarantorKind::SelfGuaranteed => "Acceptance self-guarantee",
                GuarantorKind::CreditProvider => "Acceptance credit provider",
            }
            .into(),
            public_key: key.verifying_key().to_bytes(),
            risk_policy_digest: hash(&[
                b"QOMM:ACCEPTANCE:RISK-POLICY:v1",
                &(index as u64).to_be_bytes(),
            ]),
        };
        let approval = approve(&facility, &authorizer, &governance, definition.statement()?)?;
        if let Some(bridge) = bridge.as_ref() {
            bridge.register_guarantor(&definition, &approval)?;
        } else {
            facility.register_guarantor(&definition, &approval)?;
        }
        guarantors.push((definition, key));
    }

    let mut group_openings = BTreeMap::<FacilityKey, AcceptanceOpening>::new();
    for maker in &authority.makers {
        let key = (maker.mandate.entity_commitment, maker.mandate.asset_id);
        match group_openings.get(&key) {
            Some(prior)
                if prior.amount != maker.acceptance_opening.amount
                    || prior.blinding != maker.acceptance_opening.blinding =>
            {
                return Err("one legal-entity facility has conflicting Maker maxima".into());
            }
            Some(_) => {}
            None => {
                group_openings.insert(key, maker.acceptance_opening.clone());
            }
        }
    }
    for taker in &authority.takers {
        let key = (
            taker.mandate.entity_commitment,
            taker.mandate.reserve_asset_id,
        );
        match group_openings.get(&key) {
            Some(prior)
                if prior.amount != taker.acceptance_opening.amount
                    || prior.blinding != taker.acceptance_opening.blinding =>
            {
                return Err("one legal-entity facility has conflicting Taker maxima".into());
            }
            Some(_) => {}
            None => {
                group_openings.insert(key, taker.acceptance_opening.clone());
            }
        }
    }
    let mut facility_plans = BTreeMap::<FacilityKey, FacilityPlan>::new();
    for (index, (key, opening)) in group_openings.iter().enumerate() {
        let asset = assets
            .get(&key.1)
            .ok_or_else(|| "mandate names an unregistered asset".to_string())?
            .clone();
        let (guarantor, guarantor_key) = &guarantors[index % guarantors.len()];
        let facility_id = hash(&[
            b"QOMM:ACCEPTANCE:FACILITY:v1",
            &key.0,
            &key.1,
            &guarantor.guarantor_id,
        ]);
        let cap_commitment = credit_commit(opening.amount, &opening.blinding);
        let collateral_blinding = opening.blinding + Scalar::from(1_u64);
        let mut grant = CreditFacilityGrant {
            operation_id: hash(&[b"QOMM:ACCEPTANCE:FACILITY-GRANT:v1", &facility_id]),
            facility_id,
            guarantor_id: guarantor.guarantor_id,
            beneficiary_commitment: key.0,
            rail_asset_id: key.1,
            cap_commitment,
            available_commitment: cap_commitment,
            held_commitment: ZERO,
            outstanding_commitment: ZERO,
            collateral_commitment: credit_commit(
                opening.amount.saturating_add(1),
                &collateral_blinding,
            ),
            risk_policy_digest: guarantor.risk_policy_digest,
            relation_proof_digest: hash(&[
                b"QOMM:ACCEPTANCE:FACILITY-GRANT-PROOF:v1",
                &facility_id,
            ]),
            valid_from: now.saturating_sub(1).max(1),
            valid_until: now.saturating_add(7_200),
            nonce: hash(&[b"QOMM:ACCEPTANCE:FACILITY-GRANT-NONCE:v1", &facility_id]),
            guarantor_signature: Signature::from_bytes(&[0_u8; 64]),
        };
        grant.guarantor_signature = guarantor_key.sign(&grant.guarantor_message()?);
        let approval = approve(&facility, &authorizer, &governance, grant.statement()?)?;
        if let Some(bridge) = bridge.as_ref() {
            bridge.grant_credit_facility(&grant, &approval, now)?;
        } else {
            facility.grant_credit_facility(&grant, &approval, now)?;
        }
        facility_plans.insert(
            *key,
            FacilityPlan {
                facility_id,
                cap_amount: opening.amount,
                cap_blinding: opening.blinding,
                asset,
            },
        );
    }

    let mut sources = BTreeMap::<OwnerKey, SourcePlan>::new();
    for maker in &authority.makers {
        let owner_key = (
            ReservationParty::Maker,
            maker.maker_index,
            maker.mandate.direction as u8,
        );
        let asset = assets
            .get(&maker.mandate.asset_id)
            .ok_or_else(|| "Maker source asset is unknown".to_string())?;
        sources.insert(
            owner_key,
            open_source_account(
                &facility,
                bridge.as_ref(),
                &authorizer,
                &governance,
                SourceAccountRequest {
                    owner_handle: maker.mandate.maker_handle,
                    asset,
                    opening: &maker.acceptance_opening,
                    discriminator: &[
                        b"maker".as_slice(),
                        &maker.maker_index.to_be_bytes(),
                        &[maker.mandate.direction as u8],
                    ]
                    .concat(),
                },
            )?,
        );
    }
    for taker in &authority.takers {
        let owner_key = (
            ReservationParty::Taker,
            taker.client_index,
            taker.mandate.direction as u8,
        );
        let asset = assets
            .get(&taker.mandate.reserve_asset_id)
            .ok_or_else(|| "Taker source asset is unknown".to_string())?;
        sources.insert(
            owner_key,
            open_source_account(
                &facility,
                bridge.as_ref(),
                &authorizer,
                &governance,
                SourceAccountRequest {
                    owner_handle: taker.mandate.taker_handle,
                    asset,
                    opening: &taker.acceptance_opening,
                    discriminator: &[
                        b"taker".as_slice(),
                        &taker.client_index.to_be_bytes(),
                        &[taker.mandate.direction as u8],
                    ]
                    .concat(),
                },
            )?,
        );
    }

    // Settlement destinations are canonical anonymous rail accounts derived
    // from the same pseudonymous handles. Open both rails before the signed
    // acknowledgement so later DvP finalization cannot smuggle in an account
    // creation or change the acknowledged pre-state.
    let mut participant_handles = authority
        .makers
        .iter()
        .map(|maker| maker.mandate.maker_handle)
        .chain(
            authority
                .takers
                .iter()
                .map(|taker| taker.mandate.taker_handle),
        )
        .collect::<Vec<_>>();
    participant_handles.sort_unstable();
    participant_handles.dedup();
    for handle in participant_handles {
        ensure_destination_account(
            &facility,
            bridge.as_ref(),
            &authorizer,
            &governance,
            handle,
            &traded_asset,
        )?;
        ensure_destination_account(
            &facility,
            bridge.as_ref(),
            &authorizer,
            &governance,
            handle,
            &cash_asset,
        )?;
    }

    let committee = AdmissionCommitteePlan {
        operation_id: hash(&[b"QOMM:ACCEPTANCE:ADMISSION-COMMITTEE:v1", &authority_digest]),
        venue_id: authority.venue_id,
        epoch: admission.epoch,
        node_keys: admission.node_keys.clone(),
        valid_from: now.saturating_sub(1).max(1),
        valid_until: now.saturating_add(3_600),
    };
    let committee_approval = approve(&facility, &authorizer, &governance, committee.statement()?)?;
    if let Some(bridge) = bridge.as_ref() {
        bridge.register_admission_committee(&committee, &committee_approval, now)?;
    } else {
        facility.register_admission_committee(&committee, &committee_approval, now)?;
    }
    let batch_id = hash(&[b"QOMM:ACCEPTANCE:ADMISSION-BATCH:v1", &authority_digest]);
    let batch = AdmissionBatchPlan {
        operation_id: hash(&[
            b"QOMM:ACCEPTANCE:ADMISSION-BATCH-OPERATION:v1",
            &authority_digest,
        ]),
        batch_id,
        venue_id: authority.venue_id,
        epoch: admission.epoch,
        slot: certified[0].slot,
        batch_digest: certified[0].cluster_digest,
        order_digest: certified[0].order_digest,
        first_sequence: certified[0].sequence,
        admission_digests: certified
            .iter()
            .map(|lane| lane.digest(authority.venue_id, admission.epoch))
            .collect::<Result<Vec<_>, _>>()?,
        expires_at: authority
            .takers
            .iter()
            .map(|taker| taker.mandate.deadline)
            .min()
            .ok_or_else(|| "pre-trade authority has no Taker deadline".to_string())?,
    };
    let batch_approval = approve(&facility, &authorizer, &governance, batch.statement()?)?;
    if let Some(bridge) = bridge.as_ref() {
        bridge.register_admission_batch(&batch, &admission.lanes, &batch_approval, now)?;
    } else {
        facility.register_admission_batch(&batch, &admission.lanes, &batch_approval, now)?;
    }

    let reserve_frost_session = hash(&[
        b"QOMM:RESERVE:FROST:DKG-SESSION:v1",
        &authority_digest,
        authorizer_domain.as_bytes(),
    ]);
    let mut reserve_signers = StdioFrostCluster::start(
        proof_party_bin,
        proof_root,
        reserve_frost_session,
        7,
        vec![1, 4, 7],
    )?;
    let public = reserve_signers.public().clone();
    let issuer = Issuer::new(Pedersen::new(b"qomm:defmi:v1"), Bounds::default());
    let venue = Venue::new(issuer.key.clone(), &issuer.bounds, public.clone());
    let mut bindings = Vec::new();

    for maker in &authority.makers {
        let facility_key = (maker.mandate.entity_commitment, maker.mandate.asset_id);
        let plan = facility_plans
            .get(&facility_key)
            .ok_or_else(|| "Maker facility was not provisioned".to_string())?;
        let source = sources
            .get(&(
                ReservationParty::Maker,
                maker.maker_index,
                maker.mandate.direction as u8,
            ))
            .ok_or_else(|| "Maker source account was not provisioned".to_string())?;
        let maker_handle = CompressedRistretto(maker.mandate.maker_handle)
            .decompress()
            .ok_or_else(|| "Maker handle is not canonical".to_string())?;
        let taker_placeholder = RistrettoPoint::mul_base(&Scalar::from(
            50_000_u64
                + u64::from(maker.maker_index) * 2
                + u64::from(maker.mandate.direction as u8),
        ));
        let mandate_digest = maker.mandate.digest()?;
        let prepared = prepare_reservation(
            facility.state_root()?,
            &issuer,
            &mut reserve_signers,
            ReserveMandateRef::Maker(&maker.mandate),
            authority.venue_id,
            authority.defmi_id,
            plan,
            source,
            &maker.acceptance_opening,
            ReservationSpec {
                role: ReservationRole::Maker,
                entity_commitment: maker.mandate.entity_commitment,
                direction: maker.mandate.direction,
                owner_handle: maker_handle,
                maker_handle,
                taker_handle: taker_placeholder,
                reserve_id: maker.mandate.reserve_id,
                authorization_digest: maker.mandate.policy_digest,
                mandate_digest,
                policy_version: maker.mandate.policy_version,
                rfq_nullifier: ZERO,
                deadline: maker.mandate.valid_until,
                admission: None,
            },
        )?;
        let receipt_digest = prepared.receipt_digest()?;
        let identity = IdentityEvidence {
            presentation: &maker.presentation,
            registry: &authority.registry,
            trusted_issuer: &trusted_kyb_issuer(),
            scope: &authority.identity_scope,
            context: &maker.identity_context,
            required_cohort: &authority.required_cohort,
        };
        let approval = approve(&facility, &authorizer, &governance, receipt_digest)?;
        if let Some(bridge) = bridge.as_ref() {
            bridge.reserve_maker(
                &prepared.transition,
                &prepared.relation_proof,
                &prepared.authorization,
                &prepared.escrow,
                &prepared.escrow_proof,
                &prepared.typed,
                &venue,
                &prepared.asset_link,
                &maker.mandate,
                &identity,
                &approval,
                now,
            )?;
        } else {
            reserve_maker(
                &facility,
                &prepared.transition,
                &prepared.relation_proof,
                &prepared.authorization,
                &prepared.escrow,
                &prepared.escrow_proof,
                &prepared.typed,
                &venue,
                &prepared.asset_link,
                &maker.mandate,
                &identity,
                &approval,
                now,
            )?;
        }
        bindings.push(PretradeReservationBinding {
            party: ReservationParty::Maker,
            owner_index: maker.maker_index,
            direction: maker.mandate.direction,
            owner_handle: maker.mandate.maker_handle,
            facility_id: plan.facility_id,
            reserve_id: maker.mandate.reserve_id,
            mandate_digest,
            policy_digest: maker.mandate.policy_digest,
            amount_commitment: maker.mandate.maximum_amount_commitment,
            reserve_receipt_digest: receipt_digest,
        });
    }

    let mut takers_by_claim = BTreeMap::<[u8; 32], &TakerPretradeAuthority>::new();
    for taker in &authority.takers {
        let digest = taker.mandate.digest()?;
        if takers_by_claim.insert(digest, taker).is_some() {
            return Err("two Taker authorities have the same mandate digest".into());
        }
    }
    let lane_by_claim = certified
        .iter()
        .map(|lane| (lane.claim_digest, lane.clone()))
        .collect::<BTreeMap<_, _>>();
    if takers_by_claim
        .keys()
        .any(|claim| !lane_by_claim.contains_key(claim))
    {
        return Err("a signed Taker mandate is absent from the certified population".into());
    }
    let mut facility_populations = BTreeMap::<FacilityKey, usize>::new();
    for taker in &authority.takers {
        *facility_populations
            .entry((
                taker.mandate.entity_commitment,
                taker.mandate.reserve_asset_id,
            ))
            .or_default() += 1;
    }
    let ordered_for = |taker: &TakerPretradeAuthority,
                       lane: &CertifiedAdmissionLane|
     -> Result<OrderedAdmission, String> {
        Ok(OrderedAdmission {
            venue_id: authority.venue_id,
            epoch: admission.epoch,
            slot: lane.slot,
            sequence: lane.sequence,
            ticket_id: lane.ticket_id,
            batch_digest: lane.cluster_digest,
            order_digest: lane.order_digest,
            rfq_nullifier: taker.mandate.rfq_nullifier,
            taker_entity_commitment: taker.mandate.entity_commitment,
            taker_mandate_digest: taker.mandate.digest()?,
            expires_at: taker.mandate.deadline,
        })
    };
    let mut prepared_takers = BTreeMap::<u16, PreparedReservation>::new();
    let mut accepted_clients = BTreeSet::new();
    let mut rejected_clients = BTreeSet::new();
    let mut consumed_lanes = 0_u64;
    for lane in &certified {
        let admission_digest = lane.digest(authority.venue_id, admission.epoch)?;
        let Some(taker) = takers_by_claim.get(&lane.claim_digest).copied() else {
            let advance = AdmissionSlotAdvance {
                operation_id: hash(&[
                    b"QOMM:ACCEPTANCE:COVER-ADVANCE:v1",
                    &batch_id,
                    &lane.sequence.to_be_bytes(),
                ]),
                batch_id,
                sequence: lane.sequence,
                admission_digest,
            };
            let approval = approve(&facility, &authorizer, &governance, advance.statement()?)?;
            let snapshot = if let Some(bridge) = bridge.as_ref() {
                bridge.advance_admission_slot(&advance, &approval, now)?.0
            } else {
                facility.advance_admission_slot(&advance, &approval, now)?
            };
            consumed_lanes = snapshot.consumed;
            continue;
        };
        let key = (
            taker.mandate.entity_commitment,
            taker.mandate.reserve_asset_id,
        );
        let population = *facility_populations
            .get(&key)
            .ok_or_else(|| "Taker facility population disappeared".to_string())?;
        if population > 1
            && !authority
                .takers
                .iter()
                .filter(|candidate| {
                    candidate.mandate.entity_commitment == key.0
                        && candidate.mandate.reserve_asset_id == key.1
                })
                .any(|candidate| prepared_takers.contains_key(&candidate.client_index))
        {
            // Simultaneous requests are prepared against the same facility
            // sequence and state root. The certified order decides which one
            // commits; the other can neither re-use that stale state nor make
            // the hidden available amount negative.
            for candidate in authority.takers.iter().filter(|candidate| {
                candidate.mandate.entity_commitment == key.0
                    && candidate.mandate.reserve_asset_id == key.1
            }) {
                let candidate_lane = lane_by_claim
                    .get(&candidate.mandate.digest()?)
                    .ok_or_else(|| "shared-cap Taker lane is missing".to_string())?;
                let plan = facility_plans
                    .get(&key)
                    .ok_or_else(|| "shared Taker facility was not provisioned".to_string())?;
                let source = sources
                    .get(&(
                        ReservationParty::Taker,
                        candidate.client_index,
                        candidate.mandate.direction as u8,
                    ))
                    .ok_or_else(|| "shared Taker source was not provisioned".to_string())?;
                let taker_handle = CompressedRistretto(candidate.mandate.taker_handle)
                    .decompress()
                    .ok_or_else(|| "Taker handle is not canonical".to_string())?;
                let maker_placeholder = RistrettoPoint::mul_base(&Scalar::from(
                    60_000_u64 + u64::from(candidate.client_index),
                ));
                let mandate_digest = candidate.mandate.digest()?;
                prepared_takers.insert(
                    candidate.client_index,
                    prepare_reservation(
                        facility.state_root()?,
                        &issuer,
                        &mut reserve_signers,
                        ReserveMandateRef::Taker(&candidate.mandate),
                        authority.venue_id,
                        authority.defmi_id,
                        plan,
                        source,
                        &candidate.acceptance_opening,
                        ReservationSpec {
                            role: ReservationRole::Taker,
                            entity_commitment: candidate.mandate.entity_commitment,
                            direction: candidate.mandate.direction,
                            owner_handle: taker_handle,
                            maker_handle: maker_placeholder,
                            taker_handle,
                            reserve_id: candidate.mandate.reserve_id,
                            authorization_digest: mandate_digest,
                            mandate_digest,
                            policy_version: 0,
                            rfq_nullifier: candidate.mandate.rfq_nullifier,
                            deadline: candidate.mandate.deadline,
                            admission: Some((ordered_for(candidate, candidate_lane)?, batch_id)),
                        },
                    )?,
                );
            }
        }
        if let std::collections::btree_map::Entry::Vacant(entry) =
            prepared_takers.entry(taker.client_index)
        {
            let plan = facility_plans
                .get(&key)
                .ok_or_else(|| "Taker facility was not provisioned".to_string())?;
            let source = sources
                .get(&(
                    ReservationParty::Taker,
                    taker.client_index,
                    taker.mandate.direction as u8,
                ))
                .ok_or_else(|| "Taker source was not provisioned".to_string())?;
            let taker_handle = CompressedRistretto(taker.mandate.taker_handle)
                .decompress()
                .ok_or_else(|| "Taker handle is not canonical".to_string())?;
            let maker_placeholder =
                RistrettoPoint::mul_base(&Scalar::from(60_000_u64 + u64::from(taker.client_index)));
            let mandate_digest = taker.mandate.digest()?;
            entry.insert(prepare_reservation(
                facility.state_root()?,
                &issuer,
                &mut reserve_signers,
                ReserveMandateRef::Taker(&taker.mandate),
                authority.venue_id,
                authority.defmi_id,
                plan,
                source,
                &taker.acceptance_opening,
                ReservationSpec {
                    role: ReservationRole::Taker,
                    entity_commitment: taker.mandate.entity_commitment,
                    direction: taker.mandate.direction,
                    owner_handle: taker_handle,
                    maker_handle: maker_placeholder,
                    taker_handle,
                    reserve_id: taker.mandate.reserve_id,
                    authorization_digest: mandate_digest,
                    mandate_digest,
                    policy_version: 0,
                    rfq_nullifier: taker.mandate.rfq_nullifier,
                    deadline: taker.mandate.deadline,
                    admission: Some((ordered_for(taker, lane)?, batch_id)),
                },
            )?);
        }
        let prepared = prepared_takers
            .remove(&taker.client_index)
            .ok_or_else(|| "Taker reservation preparation disappeared".to_string())?;
        let ordered = ordered_for(taker, lane)?;
        let receipt_digest = prepared.receipt_digest()?;
        let before_attempt = facility.state_root()?;
        let identity = IdentityEvidence {
            presentation: &taker.presentation,
            registry: &authority.registry,
            trusted_issuer: &trusted_kyb_issuer(),
            scope: &authority.identity_scope,
            context: &taker.identity_context,
            required_cohort: &authority.required_cohort,
        };
        let approval = approve(&facility, &authorizer, &governance, receipt_digest)?;
        let result = if let Some(bridge) = bridge.as_ref() {
            bridge
                .reserve_taker(
                    &prepared.transition,
                    &prepared.relation_proof,
                    &prepared.authorization,
                    &prepared.escrow,
                    &prepared.escrow_proof,
                    &prepared.typed,
                    &venue,
                    &prepared.asset_link,
                    &ordered,
                    &taker.mandate,
                    &identity,
                    &approval,
                    now,
                )
                .map(|_| ())
        } else {
            reserve_taker(
                &facility,
                &prepared.transition,
                &prepared.relation_proof,
                &prepared.authorization,
                &prepared.escrow,
                &prepared.escrow_proof,
                &prepared.typed,
                &venue,
                &prepared.asset_link,
                &ordered,
                &taker.mandate,
                &identity,
                &approval,
                now,
            )
            .map(|_| ())
        };
        match result {
            Ok(_) => {
                accepted_clients.insert(taker.client_index);
                bindings.push(PretradeReservationBinding {
                    party: ReservationParty::Taker,
                    owner_index: taker.client_index,
                    direction: taker.mandate.direction,
                    owner_handle: taker.mandate.taker_handle,
                    facility_id: facility_plans[&key].facility_id,
                    reserve_id: taker.mandate.reserve_id,
                    mandate_digest: taker.mandate.digest()?,
                    policy_digest: ZERO,
                    amount_commitment: taker.mandate.maximum_amount_commitment,
                    reserve_receipt_digest: receipt_digest,
                });
                consumed_lanes = lane.sequence;
            }
            Err(error) if population > 1 => {
                if facility.state_root()? != before_attempt {
                    return Err("rejected shared-cap RFQ changed authoritative state".into());
                }
                let advance = AdmissionSlotAdvance {
                    operation_id: hash(&[
                        b"QOMM:ACCEPTANCE:CAP-REJECTION-ADVANCE:v1",
                        &batch_id,
                        &lane.sequence.to_be_bytes(),
                    ]),
                    batch_id,
                    sequence: lane.sequence,
                    admission_digest,
                };
                let approval = approve(&facility, &authorizer, &governance, advance.statement()?)?;
                let snapshot = if let Some(bridge) = bridge.as_ref() {
                    bridge.advance_admission_slot(&advance, &approval, now)?.0
                } else {
                    facility.advance_admission_slot(&advance, &approval, now)?
                };
                consumed_lanes = snapshot.consumed;
                rejected_clients.insert(taker.client_index);
                eprintln!(
                    "shared-cap RFQ {} rejected without state leakage: {}",
                    taker.client_index, error
                );
            }
            Err(error) => return Err(format!("independent Taker reservation failed: {error}")),
        }
    }
    if consumed_lanes != certified.len() as u64
        || accepted_clients.len() != 2
        || rejected_clients.len() != 1
        || accepted_clients
            .intersection(&rejected_clients)
            .next()
            .is_some()
    {
        return Err(
            "fixed population or shared legal-entity cap did not reach the expected state".into(),
        );
    }

    let acknowledgement = PretradeAcknowledgement {
        authority_digest,
        defmi_id: authority.defmi_id,
        after_state_root: facility.state_root()?,
        bindings,
        signer_public: signing_receipts.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0_u8; 64]),
    }
    .sign(&signing_receipts)?;
    acknowledgement.verify(&signing_receipts.verifying_key())?;
    if !facility.verify_receipt_chain()? {
        return Err("DeFMI receipt chain failed after pre-trade reservations".into());
    }
    let reserve_public_digest: [u8; 32] = Sha256::digest(
        public
            .serialize()
            .map_err(|_| "reserve FROST public package cannot be serialized")?,
    )
    .into();
    reserve_signers.close()?;
    let report = json!({
        "version": 1,
        "authoritative_backend": if avalanche_client.is_some() { "avalanche_l1" } else { "local_sqlite" },
        "authorizer_domain": authorizer_domain,
        "authority_digest": hex::encode(authority_digest),
        "after_state_root": hex::encode(acknowledgement.after_state_root),
        "admission_population": certified.len(),
        "admission_consumed": consumed_lanes,
        "accepted_taker_clients": accepted_clients,
        "rejected_taker_clients": rejected_clients,
        "maker_reservations": authority.makers.len(),
        "reserve_zkpi_signing": {
            "process_isolated_parties": 7,
            "threshold": 3,
            "central_secret_share_collection": false,
            "public_package_digest": hex::encode(reserve_public_digest),
        },
        "guarantor_kinds": ["ccp", "bank", "self"],
        "external_identity": {
            "provider": authority.identity_provider,
            "evidence_digest": hex::encode(authority.identity_evidence_digest),
            "raw_legal_entity_identifier_disclosed": false,
            "anonymous_scope_nullifier": true,
        },
        "legal_entity_cap_key": "entity_commitment + guarantor_id + rail_asset_id",
        "state_database": state_path.display().to_string(),
    });
    Ok((acknowledgement, report))
}

fn required_path(arguments: &[String], name: &str) -> Result<PathBuf, String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|position| arguments.get(position + 1))
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required"))
}

fn optional_string(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|position| arguments.get(position + 1))
        .cloned()
}

fn flag(arguments: &[String], name: &str) -> bool {
    arguments.iter().any(|argument| argument == name)
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let authority_path = required_path(&arguments, "--authority")?;
    let acknowledgement_path = required_path(&arguments, "--ack-out")?;
    let state_path = required_path(&arguments, "--state")?;
    let report_path = required_path(&arguments, "--report-out")?;
    let proof_party_bin = required_path(&arguments, "--proof-party-bin")?;
    let proof_root = required_path(&arguments, "--proof-root")?;
    if !proof_party_bin.is_file() {
        return Err("--proof-party-bin must name an executable proof-party host".into());
    }
    let avalanche_endpoint = optional_string(&arguments, "--avalanche-endpoint");
    let avalanche_domain = optional_string(&arguments, "--avalanche-domain");
    let account_free_notes = flag(&arguments, "--account-free-notes");
    let csd_signer = if account_free_notes {
        let executable = required_path(&arguments, "--csd-signer-bin")?;
        let store = required_path(&arguments, "--csd-signer-store")?;
        let pin = required_path(&arguments, "--csd-signer-pin-file")?;
        let key_id = optional_string(&arguments, "--csd-signer-key-id")
            .ok_or_else(|| "--csd-signer-key-id is required".to_string())?;
        let public: [u8; 32] = hex::decode(
            optional_string(&arguments, "--csd-signer-public")
                .ok_or_else(|| "--csd-signer-public is required".to_string())?,
        )
        .map_err(|_| "CSD signer public key is not hexadecimal".to_string())?
        .try_into()
        .map_err(|_| "CSD signer public key is not 32 bytes".to_string())?;
        let public = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| "CSD signer public key is malformed".to_string())?;
        Some(CommandEd25519Signer::new(
            executable,
            vec![
                "--store".into(),
                store.display().to_string(),
                "--pin-file".into(),
                pin.display().to_string(),
                "--key-id".into(),
                key_id.clone(),
            ],
            key_id,
            public,
            Duration::from_secs(5),
        )?)
    } else {
        None
    };
    if avalanche_endpoint.is_some() != avalanche_domain.is_some() {
        return Err("--avalanche-endpoint and --avalanche-domain must be provided together".into());
    }
    for (name, path) in [
        ("acknowledgement", &acknowledgement_path),
        ("state database", &state_path),
        ("report", &report_path),
    ] {
        if path.exists() {
            return Err(format!(
                "refusing to overwrite an existing {name}: {}",
                path.display()
            ));
        }
    }
    let authority = read_authority_private(&authority_path)?;
    let avalanche_client = avalanche_endpoint
        .as_deref()
        .map(|endpoint| AvalancheRpcClient::new(endpoint, Duration::from_secs(30), true))
        .transpose()?;
    let authorizer_domain = avalanche_domain.as_deref().unwrap_or("defmi:qomm-live-v1");
    let (acknowledgement, report) = process_authority(AuthorityProcessing {
        authority: &authority,
        state_path: &state_path,
        avalanche_client: avalanche_client.as_ref(),
        authorizer_domain,
        proof_party_bin: &proof_party_bin,
        proof_root: &proof_root,
        account_free_notes,
        csd_signer: csd_signer
            .as_ref()
            .map(|signer| signer as &dyn Ed25519MessageSigner),
    })?;
    write_ack_private(&acknowledgement_path, &acknowledgement)?;
    let report_bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&report_path, report_bytes).map_err(|error| error.to_string())?;
    println!(
        "DeFMI pre-trade acknowledgement: {}",
        acknowledgement_path.display()
    );
    println!("DeFMI reservation report: {}", report_path.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("DeFMI pre-trade reservation failed: {error}");
        std::process::exit(1);
    }
}
