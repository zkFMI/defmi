//! Coordinator-side assembly of verifier-complete product proofs.
//!
//! The coordinator relays commitments and public proof messages.  It never
//! receives a Shamir share, pricing-policy opening, quote, reserve opening, or
//! a FROST signing-key share.  Stateful proof operations live in seven
//! independent [`ProofPartyRpc`] implementations.

use crate::dvp_issuer::{
    assemble_proofs as assemble_dvp_proofs, make_challenge as make_dvp_challenge,
    relation_statements_from_evaluations as dvp_relation_statements,
    statements_from_evaluations as dvp_statements, DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT,
    DVP_SECURITIES_REMAINDER_CONTEXT,
};
use crate::dvp_wire::{
    decode as decode_dvp, encode as encode_dvp, Envelope as DvpEnvelope, Message as DvpMessage,
};
use crate::frost_coordinator::{distributed_frost_sign, frost_signing_job};
use crate::limit_issuer::{
    assemble as assemble_limit, challenge as make_limit_challenge,
    relation_from_evaluations as limit_relations, statement_from_evaluations as limit_statement,
};
use crate::limit_wire::{
    decode as decode_limit, encode as encode_limit, Envelope as LimitEnvelope,
    Message as LimitMessage,
};
use crate::mandate::MakerPolicyMandate;
use crate::order::{
    complete_quote_context, decode_node_execution_attestation, derive_execution_lane,
    encode_execution_attestations, live_proof_job_id, verify_execution_lane,
    NodeExecutionAttestation,
};
use crate::pretrade_authority::{encode_ack, PretradeAcknowledgement};
use crate::proof_client::ProofPartyRpc;
use crate::proof_codec::{encode_dvp_proofs, encode_threshold_range, QuoteVerificationBundle};
use crate::quote_wire::{
    decode as decode_quote, encode as encode_quote, Envelope as QuoteEnvelope,
    Message as QuoteMessage,
};
use crate::settlement_handoff::SettlementHandoff;
use crate::standing_pool::{StandingPoolAllocationBinding, STANDING_POOL_REMAINDER_CONTEXT};
use crate::zkpi_issuer::{
    assemble_ranges, build_partial_instruction, make_challenge as make_zkpi_challenge,
    relation_statements_from_evaluations as zkpi_relation_statements,
    statements_from_evaluations as zkpi_statements,
};
use crate::zkpi_wire::{
    decode as decode_zkpi, encode as encode_zkpi, Envelope as ZkpiEnvelope, Message as ZkpiMessage,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use merlin::Transcript;
use qomm_mpc::program::{PRODUCT_ZKPI_AMOUNT_BITS, PRODUCT_ZKPI_PRICE_BITS};
use qomm_proofs::opening_envelope::{opening_context, EncryptedOpeningShare, OpeningEnvelope};
use qomm_proofs::price_limit::{
    from_threshold as threshold_price_limit, threshold_context as price_limit_context,
    PriceLimitDirection,
};
use qomm_proofs::quote_proof::{
    registry_digest, Public as QuotePublic, QuoteCircuit, RegisteredPolicy,
};
use qomm_proofs::threshold_gadgets::coefficient_commitments_from_evaluations;
use qomm_proofs::threshold_quote::{
    assemble_quote_from_rounds, make_quote_challenges, quote_relation_statements_from_evaluations,
    quote_statement_from_evaluations, QuoteChallengeTranscript,
};
use qomm_proofs::threshold_range::verify_threshold_range;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_product;
use qomm_zkpi::{
    asset_scalar, frost, typed, typed_wire, Bounds, PartialInstruction, QuoteBinding, Venue,
    DEFAULT_DOMAIN,
};
use rand_core::OsRng;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const COMMITTEE_SIZE: usize = 7;
const SHAMIR_THRESHOLD: usize = 2;
const SIGNING_QUORUM: [usize; 3] = [1, 4, 7];
const MAX_PUBLIC_WIRE_BYTES: usize = 1 << 20;

/// Public inputs required to prove that the MPC-selected quote is complete and
/// minimal among all eligible registered policies.
pub struct CompleteQuoteRequest {
    pub job_id: [u8; 32],
    pub request_context: [u8; 32],
    pub public: QuotePublic,
    pub winner_index: usize,
    pub winner_value: u64,
    /// Proof-party configuration width.  Two bits are reserved for boolean
    /// eligibility gates; the remaining bits constrain the signed cost.
    pub eligibility_bits: usize,
    pub span_bits: usize,
}

#[derive(Clone, Debug)]
pub struct RegisteredPolicyOpening {
    pub maker_asset: u32,
    /// ask level, spread, slope, inventory coefficient, inventory, maximum
    /// quantity, expiry, active flag and reference-price flag.
    pub values: [i64; 9],
    pub blindings: [u64; 9],
}

pub struct CompleteQuotePublicInput {
    pub job_id: [u8; 32],
    pub request_context: [u8; 32],
    pub quantity: i64,
    pub quantity_blinding: u64,
    pub now: i64,
    pub sentinel: i64,
    pub direction: u8,
    pub asset: u32,
    pub reference_price: i64,
    pub policies: Vec<RegisteredPolicyOpening>,
    pub market_digest: [u8; 32],
    pub slot: u64,
    pub winner_index: usize,
    pub winner_value: u64,
    pub eligibility_bits: usize,
    pub span_bits: usize,
}

/// Public settlement metadata supplied after the complete-quote proof has
/// been accepted by all seven proof parties.  Amount, price, reserve openings,
/// selected Maker policy and inventory remain in node-local MPC persistence.
pub struct ProductSettlementRequest {
    pub job_id: [u8; 32],
    pub admission_sequence: u64,
    pub admission_ticket_id: [u8; 32],
    pub quote_verification: QuoteVerificationBundle,
    pub limit_direction: PriceLimitDirection,
    pub limit_commitment: RistrettoPoint,
    /// Signed Taker mandate digest.  It is also the price-limit transcript
    /// context and cannot be replaced after observing the match.
    pub limit_context: [u8; 32],
    pub taker_handle: RistrettoPoint,
    pub asset_id: [u8; 32],
    pub deadline: u64,
    pub now: u64,
    pub execution: ProductExecutionRequest,
}

/// Deterministic public fields of one seven-node MPC execution. The canonical
/// proof job identifier is derived from this statement before any quote or
/// settlement proof is created, then checked again against all seven signed
/// node attestations.
pub struct ProductExecutionRequest {
    pub lane: usize,
    pub slot: u64,
    pub generation: u64,
    pub frame_count: u64,
    pub input_count: u64,
    pub order_digest: [u8; 32],
    pub nodes: Vec<ExecutionAttestationInput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionAttestationInput {
    pub batch_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub stdout_digest: [u8; 32],
    pub stderr_digest: [u8; 32],
    pub persistence_digest: [u8; 32],
}

pub struct ProductSettlementProof {
    pub handoff: SettlementHandoff,
    pub execution_attestations: Vec<u8>,
    pub execution_node_keys: Vec<[u8; 32]>,
}

/// Ask the same proof quorum that produced the quote and DvP evidence to
/// authorize one exact child allocation from the winning Maker's standing
/// DeFMI note pool.  Each selected node independently checks the signed Maker
/// mandate, winner, quote proof, DvP proof, parent conservation equation and
/// non-negative parent remainder before releasing a FROST share.
pub fn authorize_standing_pool_allocation<T: ProofPartyRpc>(
    parties: &mut [T],
    handoff: &SettlementHandoff,
    maker_mandate: &MakerPolicyMandate,
    binding: &StandingPoolAllocationBinding,
) -> Result<frost::Signature, String> {
    if parties.len() != COMMITTEE_SIZE {
        return Err("standing-pool authorization requires exactly seven parties".into());
    }
    binding.validate()?;
    if binding.proof_job_id != handoff.job_id
        || binding.quote_proof_digest != handoff.quote_digest
        || binding.remainder_note.value_commitment
            != handoff.maker_pool_remainder.compress().to_bytes()
    {
        return Err("standing-pool binding differs from the completed public proof".into());
    }
    let message = binding.signing_message()?;
    let signing_job = frost_signing_job(&message);
    let payment = qomm_zkpi::wire::encode(&handoff.instruction);
    let dvp_proofs = encode_dvp_proofs(&handoff.dvp_proofs)?;
    let pool_remainder_range = encode_threshold_range(&handoff.maker_pool_remainder_proof)?;
    let mandate_unsigned = maker_mandate.unsigned()?;
    let params = json!({
        "job_id": hex::encode(handoff.job_id),
        "signing_job_id": hex::encode(signing_job),
        "message": BASE64.encode(message),
        "allocation_binding": binding.body()?,
        "payment": BASE64.encode(payment),
        "dvp_proofs": BASE64.encode(dvp_proofs),
        "pool_remainder_range": BASE64.encode(pool_remainder_range),
        "role": "maker",
        "mandate_unsigned": BASE64.encode(mandate_unsigned),
        "mandate_signature": hex::encode(maker_mandate.signature.to_bytes()),
    });
    for party in SIGNING_QUORUM {
        let value =
            parties[party - 1].call("authorize_standing_pool_allocation", params.clone())?;
        if value.get("authorized").and_then(Value::as_bool) != Some(true) {
            return Err("proof party did not authorize the standing-pool allocation".into());
        }
    }
    let signature =
        distributed_frost_sign(parties, &SIGNING_QUORUM, &message, &handoff.frost_public)?;
    handoff
        .frost_public
        .verifying_key()
        .verify(&message, &signature)
        .map_err(|_| "standing-pool FROST signature is invalid".to_string())?;
    Ok(signature)
}

/// Durably close one active proof job after every pre-settlement authorization
/// that depends on its node-local commitments has been issued.  In particular,
/// a Maker standing-pool split must be authorized before this call; completed
/// records intentionally retain only the minimum typed-settlement evidence.
pub fn complete_product_proof<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
) -> Result<(), String> {
    if parties.len() != COMMITTEE_SIZE {
        return Err("product proof completion requires exactly seven parties".into());
    }
    for (index, party) in parties.iter_mut().enumerate() {
        let party_number = index + 1;
        let signer = SIGNING_QUORUM.contains(&party_number);
        let operation = if signer {
            "complete"
        } else {
            "complete_observer"
        };
        let value = party.call(operation, json!({"job_id": hex::encode(job_id)}))?;
        let accepted = if signer {
            value.get("completed")
        } else {
            value.get("observer_completed")
        };
        if accepted.and_then(Value::as_bool) != Some(true) {
            return Err(if signer {
                "signing proof party did not durably complete the product proof".into()
            } else {
                "observer proof party did not durably close the product proof".into()
            });
        }
    }
    Ok(())
}

/// Bind a completed MPC proof to authoritative DeFMI reservations and produce
/// the final typed 3-of-7 authorization.  This happens after proof parties
/// have durably completed the quote/zkPI/DvP proof, so they can refuse any
/// context that substitutes another Maker, Taker, policy, reservation receipt,
/// or DeFMI state root.
pub fn finalize_product_settlement<T: ProofPartyRpc>(
    parties: &mut [T],
    handoff: &mut SettlementHandoff,
    context: qomm_zkpi::typed::ExecutionContext,
    acknowledgement: &PretradeAcknowledgement,
    trusted_defmi: &VerifyingKey,
) -> Result<(), String> {
    if parties.len() != COMMITTEE_SIZE {
        return Err("typed product settlement requires exactly seven parties".into());
    }
    if handoff.execution_context.is_some() || handoff.typed_authorization.is_some() {
        return Err("product settlement handoff was already finalized".into());
    }
    acknowledgement.verify(trusted_defmi)?;
    context
        .validate_against(&handoff.instruction)
        .map_err(str::to_string)?;
    let message = typed::digest_for(&handoff.instruction, &context, DEFAULT_DOMAIN)
        .map_err(str::to_string)?;
    let signing_job = frost_signing_job(&message);
    let payment_wire = qomm_zkpi::wire::encode(&handoff.instruction);
    let context_wire = typed_wire::encode_context(&context);
    let acknowledgement_wire = encode_ack(acknowledgement)?;
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "authorize_typed",
            json!({
                "job_id": hex::encode(handoff.job_id),
                "signing_job_id": hex::encode(signing_job),
                "message": BASE64.encode(message),
                "payment": BASE64.encode(&payment_wire),
                "context": BASE64.encode(&context_wire),
                "pretrade_ack": BASE64.encode(&acknowledgement_wire),
            }),
        )?;
        if value.get("authorized").and_then(Value::as_bool) != Some(true) {
            return Err("proof party did not authorize the typed settlement".into());
        }
    }
    let authorization =
        distributed_frost_sign(parties, &SIGNING_QUORUM, &message, &handoff.frost_public)?;
    handoff
        .frost_public
        .verifying_key()
        .verify(&message, &authorization)
        .map_err(|_| "typed product settlement signature is invalid".to_string())?;
    handoff.execution_context = Some(context);
    handoff.typed_authorization = Some(authorization);
    handoff.typed_instruction()?;
    Ok(())
}

impl ProductExecutionRequest {
    fn receipt_statements(&self) -> Result<Vec<NodeExecutionAttestation>, String> {
        if self.lane > 4095
            || u32::try_from(self.slot).is_err()
            || self.generation == 0
            || self.frame_count == 0
            || self.input_count == 0
            || self.order_digest == [0_u8; 32]
            || self.nodes.len() != COMMITTEE_SIZE
            || self.nodes.iter().any(|node| {
                [
                    node.batch_digest,
                    node.source_digest,
                    node.stdout_digest,
                    node.stderr_digest,
                    node.persistence_digest,
                ]
                .contains(&[0_u8; 32])
            })
        {
            return Err("product execution request is outside its fixed bounds".into());
        }
        self.nodes
            .iter()
            .enumerate()
            .map(|(node, input)| {
                let mut statement = NodeExecutionAttestation {
                    node: u16::try_from(node)
                        .map_err(|_| "execution node index exceeds u16".to_string())?,
                    slot: self.slot,
                    lane: u64::try_from(self.lane)
                        .map_err(|_| "execution lane exceeds u64".to_string())?,
                    batch_digest: input.batch_digest,
                    source_digest: input.source_digest,
                    state_generation: self.generation,
                    frame_count: self.frame_count,
                    input_count: self.input_count,
                    stdout_digest: input.stdout_digest,
                    stderr_digest: input.stderr_digest,
                    persistence_digest: input.persistence_digest,
                    receipt_digest: [0_u8; 32],
                    signature: Signature::from_bytes(&[0_u8; 64]),
                };
                statement.receipt_digest = statement.recompute_receipt_digest()?;
                Ok(statement)
            })
            .collect()
    }

    /// Canonical one-use proof identifier expected by proof parties and the
    /// DeFMI/Avalanche verifier for this exact signed execution lane.
    pub fn job_id(&self) -> Result<[u8; 32], String> {
        let lane = derive_execution_lane(&self.receipt_statements()?, self.order_digest)?;
        live_proof_job_id(
            u32::try_from(lane.slot)
                .map_err(|_| "execution receipt slot is outside the MPC range".to_string())?,
            usize::try_from(lane.lane)
                .map_err(|_| "execution receipt lane exceeds usize".to_string())?,
            lane.digest,
        )
    }
}

impl ProductSettlementRequest {
    fn validate(&self) -> Result<[u8; 32], String> {
        if self.job_id == [0_u8; 32]
            || self.admission_sequence == 0
            || self.admission_ticket_id == [0_u8; 32]
            || self.limit_context == [0_u8; 32]
            || self.asset_id == [0_u8; 32]
            || self.taker_handle == RistrettoPoint::default()
            || self.deadline < self.now
            || self.deadline > self.now.saturating_add(3_600)
            || self.execution.job_id()? != self.job_id
        {
            return Err("product settlement request is outside its fixed bounds".into());
        }
        self.quote_verification.verify()
    }
}

fn signed_scalar(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value as u64)
    }
}

/// Commit clear registration inputs before discarding their openings from the
/// coordinator. Production deployments receive the same commitments from the
/// DeFMI policy registry; the Docker demonstration builds them locally from
/// the Maker-submitted shares.
pub fn complete_quote_request(
    input: CompleteQuotePublicInput,
) -> Result<CompleteQuoteRequest, String> {
    if input.policies.is_empty()
        || input.policies.len() > 4096
        || input.direction > 1
        || input.winner_index >= input.policies.len()
        || input
            .policies
            .iter()
            .any(|policy| !matches!(policy.values[7], 0 | 1) || !matches!(policy.values[8], 0 | 1))
    {
        return Err("quote registration openings are outside their fixed bounds".into());
    }
    let key = Pedersen::new(b"qomm:policy:v1");
    let registry = input
        .policies
        .iter()
        .map(|policy| {
            let commit = |field: usize| {
                key.commit(
                    &signed_scalar(policy.values[field]),
                    &Scalar::from(policy.blindings[field]),
                )
            };
            RegisteredPolicy {
                maker_asset: policy.maker_asset,
                ask_level: commit(0),
                spread: commit(1),
                slope: commit(2),
                invcoef: commit(3),
                inv: commit(4),
                maxqty: commit(5),
                expiry: commit(6),
                active: commit(7),
                use_ref: commit(8),
            }
        })
        .collect::<Vec<_>>();
    let public = QuotePublic {
        qty_commitment: key.commit(
            &signed_scalar(input.quantity),
            &Scalar::from(input.quantity_blinding),
        ),
        now: input.now,
        sentinel: input.sentinel,
        n_slots: i64::try_from(registry.len()).map_err(|_| "quote registry length exceeds i64")?,
        direction: input.direction,
        asset: input.asset,
        reference_price: input.reference_price,
        registry_digest: registry_digest(&registry),
        registry,
        market_digest: input.market_digest,
        slot: input.slot,
    };
    let request = CompleteQuoteRequest {
        job_id: input.job_id,
        request_context: input.request_context,
        public,
        winner_index: input.winner_index,
        winner_value: input.winner_value,
        eligibility_bits: input.eligibility_bits,
        span_bits: input.span_bits,
    };
    request.validate()?;
    Ok(request)
}

impl CompleteQuoteRequest {
    fn validate(&self) -> Result<(), String> {
        if self.job_id == [0_u8; 32]
            || self.request_context == [0_u8; 32]
            || self.public.registry.is_empty()
            || self.public.registry.len() > 4096
            || usize::try_from(self.public.n_slots).ok() != Some(self.public.registry.len())
            || self.winner_index >= self.public.registry.len()
            || self.eligibility_bits < 3
            || self.eligibility_bits > 64
            || !(1..=64).contains(&self.span_bits)
        {
            return Err("complete quote request is outside its fixed bounds".into());
        }
        Ok(())
    }
}

fn public_wire(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    let raw = BASE64
        .decode(
            value
                .as_str()
                .ok_or_else(|| format!("proof-party {name} is not a public wire"))?,
        )
        .map_err(|_| format!("proof-party {name} is not valid base64"))?;
    if raw.is_empty() || raw.len() > MAX_PUBLIC_WIRE_BYTES {
        return Err(format!("proof-party {name} exceeds its fixed bound"));
    }
    Ok(raw)
}

fn wire_array(wires: &[Vec<u8>]) -> Value {
    Value::Array(
        wires
            .iter()
            .map(|wire| Value::String(BASE64.encode(wire)))
            .collect(),
    )
}

fn public_json(request: &CompleteQuoteRequest) -> Value {
    let public = &request.public;
    let registry = public
        .registry
        .iter()
        .map(|policy| {
            json!({
                "maker_asset": policy.maker_asset,
                "ask_level": hex::encode(policy.ask_level.compress().to_bytes()),
                "spread": hex::encode(policy.spread.compress().to_bytes()),
                "slope": hex::encode(policy.slope.compress().to_bytes()),
                "invcoef": hex::encode(policy.invcoef.compress().to_bytes()),
                "inv": hex::encode(policy.inv.compress().to_bytes()),
                "maxqty": hex::encode(policy.maxqty.compress().to_bytes()),
                "expiry": hex::encode(policy.expiry.compress().to_bytes()),
                "active": hex::encode(policy.active.compress().to_bytes()),
                "use_ref": hex::encode(policy.use_ref.compress().to_bytes()),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "qty_commitment": hex::encode(public.qty_commitment.compress().to_bytes()),
        "now": public.now,
        "sentinel": public.sentinel,
        "n_slots": public.n_slots,
        "direction": public.direction,
        "asset": public.asset,
        "reference_price": public.reference_price,
        "registry": registry,
        "registry_digest": hex::encode(public.registry_digest),
        "market_digest": hex::encode(public.market_digest),
        "slot": public.slot,
        "winner_index": request.winner_index,
        "winner_value": request.winner_value,
    })
}

fn cross_quote(job_id: [u8; 32], message: QuoteMessage) -> Result<QuoteMessage, String> {
    let raw = encode_quote(&QuoteEnvelope { job_id, message })?;
    let decoded = decode_quote(&raw)?;
    if decoded.job_id != job_id {
        return Err("quote public message crossed into another job".into());
    }
    Ok(decoded.message)
}

/// Assemble and independently verify a complete-quote proof from seven
/// resident proof parties.
pub fn prove_complete_quote<T: ProofPartyRpc>(
    parties: &mut [T],
    request: &CompleteQuoteRequest,
) -> Result<QuoteVerificationBundle, String> {
    request.validate()?;
    if parties.len() != COMMITTEE_SIZE {
        return Err("complete quote proof requires exactly seven parties".into());
    }
    let circuit = QuoteCircuit::try_new(request.eligibility_bits - 2, request.span_bits)
        .map_err(str::to_string)?;
    let quote_context = complete_quote_context(request.job_id, request.request_context);
    let evaluation_wires = parties
        .iter_mut()
        .map(|party| {
            party
                .call(
                    "quote_evaluations",
                    json!({"job_id": hex::encode(request.job_id)}),
                )
                .and_then(|value| public_wire(&value, "quote evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let evaluations = evaluation_wires
        .iter()
        .map(|raw| match decode_quote(raw)? {
            QuoteEnvelope {
                job_id,
                message: QuoteMessage::Evaluations(value),
            } if job_id == request.job_id => Ok(value),
            _ => Err("quote proof party returned another evaluation type".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let committee = (1..=parties.len()).collect::<Vec<_>>();
    let statement = quote_statement_from_evaluations(
        &circuit,
        &evaluations,
        &request.public,
        request.winner_index,
        request.winner_value,
        &committee,
        SHAMIR_THRESHOLD,
    )?;
    let public = public_json(request);
    let relation_wires = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "quote_bind",
                json!({
                    "job_id": hex::encode(request.job_id),
                    "evaluations": wire_array(&evaluation_wires),
                    "public": public.clone(),
                    "quote_context": BASE64.encode(quote_context),
                }),
            )?;
            public_wire(&value, "quote relation evaluation")
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relation_evaluations = relation_wires
        .iter()
        .map(|raw| match decode_quote(raw)? {
            QuoteEnvelope {
                job_id,
                message: QuoteMessage::RelationEvaluations(value),
            } if job_id == request.job_id => Ok(value),
            _ => Err("quote proof party returned another relation type".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relations = quote_relation_statements_from_evaluations(
        &circuit,
        &statement,
        &request.public,
        &relation_evaluations,
    )?;
    for party in parties.iter_mut() {
        let value = party.call(
            "quote_relation_bind",
            json!({
                "job_id": hex::encode(request.job_id),
                "evaluations": wire_array(&relation_wires),
            }),
        )?;
        if value.get("bound").and_then(Value::as_bool) != Some(true) {
            return Err("quote proof party did not bind its relation statement".into());
        }
    }

    let mut seal_wires = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut round_wires = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut seals = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut rounds = Vec::with_capacity(SIGNING_QUORUM.len());
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "quote_round1",
            json!({"job_id": hex::encode(request.job_id)}),
        )?;
        let seal_wire = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "quote proof party omitted its round-one seal".to_string())?,
            "quote round-one seal",
        )?;
        let round_wire = public_wire(
            value
                .get("round")
                .ok_or_else(|| "quote proof party omitted round one".to_string())?,
            "quote round one",
        )?;
        seals.push(match decode_quote(&seal_wire)? {
            QuoteEnvelope {
                job_id,
                message: QuoteMessage::Round1Seal(value),
            } if job_id == request.job_id => value,
            _ => return Err("quote proof party returned another seal type".into()),
        });
        rounds.push(match decode_quote(&round_wire)? {
            QuoteEnvelope {
                job_id,
                message: QuoteMessage::Round1(value),
            } if job_id == request.job_id => value,
            _ => return Err("quote proof party returned another round-one type".into()),
        });
        seal_wires.push(seal_wire);
        round_wires.push(round_wire);
    }
    let challenge = make_quote_challenges(
        &circuit,
        &statement,
        &relations,
        &request.public,
        QuoteChallengeTranscript {
            rounds: &rounds,
            seals: &seals,
            quorum: &SIGNING_QUORUM,
            context: &quote_context,
        },
    )?;
    let challenge = match cross_quote(request.job_id, QuoteMessage::Challenge(challenge))? {
        QuoteMessage::Challenge(value) => value,
        _ => return Err("quote wire changed the challenge type".into()),
    };
    let challenge_wire = encode_quote(&QuoteEnvelope {
        job_id: request.job_id,
        message: QuoteMessage::Challenge(challenge),
    })?;
    let mut response_wires = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut responses = Vec::with_capacity(SIGNING_QUORUM.len());
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "quote_round2",
            json!({
                "job_id": hex::encode(request.job_id),
                "challenge": BASE64.encode(&challenge_wire),
            }),
        )?;
        let wire = public_wire(&value, "quote round two")?;
        responses.push(match decode_quote(&wire)? {
            QuoteEnvelope {
                job_id,
                message: QuoteMessage::Round2(value),
            } if job_id == request.job_id => value,
            _ => return Err("quote proof party returned another response type".into()),
        });
        response_wires.push(wire);
    }
    let proof = assemble_quote_from_rounds(
        &circuit,
        &statement,
        &relations,
        &request.public,
        &rounds,
        &seals,
        &responses,
        &SIGNING_QUORUM,
        &quote_context,
    )?;
    let bundle = QuoteVerificationBundle {
        context: quote_context,
        eligibility_bits: request.eligibility_bits - 2,
        span_bits: request.span_bits,
        public: request.public.clone(),
        proof,
    };
    let expected_digest = hex::encode(bundle.verify()?);
    for party in parties.iter_mut() {
        let value = party.call(
            "quote_finalize",
            json!({
                "job_id": hex::encode(request.job_id),
                "rounds": wire_array(&round_wires),
                "seals": wire_array(&seal_wires),
                "responses": wire_array(&response_wires),
                "quorum": SIGNING_QUORUM,
            }),
        )?;
        if value.get("quote_digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
            return Err("proof parties finalized different complete quote proofs".into());
        }
    }
    Ok(bundle)
}

fn cross_zkpi(job_id: [u8; 32], message: ZkpiMessage) -> Result<ZkpiMessage, String> {
    let raw = encode_zkpi(&ZkpiEnvelope { job_id, message }).map_err(|error| error.to_string())?;
    let decoded = decode_zkpi(&raw).map_err(|error| error.to_string())?;
    if decoded.job_id != job_id {
        return Err("zkPI public message crossed into another job".into());
    }
    Ok(decoded.message)
}

fn cross_dvp(job_id: [u8; 32], message: DvpMessage) -> Result<DvpMessage, String> {
    let raw = encode_dvp(&DvpEnvelope { job_id, message }).map_err(|error| error.to_string())?;
    let decoded = decode_dvp(&raw).map_err(|error| error.to_string())?;
    if decoded.job_id != job_id {
        return Err("DvP public message crossed into another job".into());
    }
    Ok(decoded.message)
}

fn authorize_zkpi<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
    partial: &PartialInstruction,
    amount_range: &[u8],
    price_range: &[u8],
) -> Result<(), String> {
    let message = partial.digest();
    let signing_job = frost_signing_job(&message);
    let quote_digest = match partial.quote_binding {
        QuoteBinding::ProofDigest(value) => value,
        QuoteBinding::LegacyPackedKey(_) => {
            return Err("proof nodes refuse legacy clear quote-key signing".into())
        }
    };
    for party in SIGNING_QUORUM {
        parties[party - 1].call(
            "authorize_zkpi",
            json!({
                "job_id": hex::encode(job_id),
                "signing_job_id": hex::encode(signing_job),
                "message": BASE64.encode(message),
                "amount_range": BASE64.encode(amount_range),
                "price_range": BASE64.encode(price_range),
                "asset_commitment": hex::encode(partial.asset_commitment.compress().to_bytes()),
                "payer_handle": hex::encode(partial.payer_handle.compress().to_bytes()),
                "payee_handle": hex::encode(partial.payee_handle.compress().to_bytes()),
                "deadline": partial.deadline,
                "nonce": hex::encode(partial.nonce),
                "quote_digest": hex::encode(quote_digest),
            }),
        )?;
    }
    Ok(())
}

fn opening_share(value: &Value) -> Result<EncryptedOpeningShare, String> {
    let decode32 = |name: &str| -> Result<[u8; 32], String> {
        hex::decode(
            value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("proof party omitted {name}"))?,
        )
        .map_err(|_| format!("proof party {name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("proof party {name} is not 32 bytes"))
    };
    Ok(EncryptedOpeningShare {
        party: value
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|party| usize::try_from(party).ok())
            .ok_or_else(|| "proof party opening identifier is invalid".to_string())?,
        ephemeral: CompressedRistretto(decode32("ephemeral")?)
            .decompress()
            .ok_or_else(|| "proof party opening ephemeral is not canonical".to_string())?,
        masked_value: Option::<Scalar>::from(Scalar::from_canonical_bytes(decode32(
            "masked_value",
        )?))
        .ok_or_else(|| "proof party opening value mask is not canonical".to_string())?,
        masked_blinding: Option::<Scalar>::from(Scalar::from_canonical_bytes(decode32(
            "masked_blinding",
        )?))
        .ok_or_else(|| "proof party opening blinding mask is not canonical".to_string())?,
    })
}

fn collect_opening<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
    leg: &str,
    recipient: RistrettoPoint,
) -> Result<OpeningEnvelope, String> {
    let context = opening_context(&job_id, leg)?;
    let recipient_wire = hex::encode(recipient.compress().to_bytes());
    let context_wire = hex::encode(context);
    let shares = SIGNING_QUORUM
        .iter()
        .map(|party_id| {
            let value = parties[*party_id - 1].call(
                "claim_opening_share",
                json!({
                    "job_id": hex::encode(job_id),
                    "leg": leg,
                    "recipient_view": recipient_wire.clone(),
                }),
            )?;
            if value.get("context").and_then(Value::as_str) != Some(context_wire.as_str())
                || value.get("recipient_view").and_then(Value::as_str)
                    != Some(recipient_wire.as_str())
            {
                return Err("proof party changed a claim-opening context or recipient".into());
            }
            opening_share(&value)
        })
        .collect::<Result<Vec<_>, String>>()?;
    OpeningEnvelope::new(context, SHAMIR_THRESHOLD + 1, recipient, shares)
}

/// Prove that the selected Maker's standing parent pool remains non-negative
/// after subtracting this RFQ's exact delivery. The witness remains split
/// across the same seven MPC proof parties; this coordinator receives only the
/// public commitment and threshold range-proof messages.
pub fn prove_standing_pool_remainder<T: ProofPartyRpc>(
    parties: &mut [T],
    key: &Pedersen,
    job_id: [u8; 32],
) -> Result<
    (
        RistrettoPoint,
        qomm_proofs::threshold_range::ThresholdRangeProof,
    ),
    String,
> {
    let evaluation_wires = parties
        .iter_mut()
        .map(|party| {
            party
                .call(
                    "pool_remainder_evaluations",
                    json!({"job_id": hex::encode(job_id)}),
                )
                .and_then(|value| public_wire(&value, "standing-pool remainder evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let evaluations = evaluation_wires
        .iter()
        .map(|raw| match decode_limit(raw)? {
            LimitEnvelope {
                job_id: wire_job,
                message: LimitMessage::Evaluations(value),
            } if wire_job == job_id => Ok(value),
            _ => Err("standing-pool proof party returned another evaluation type".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let statement = limit_statement(&evaluations, SHAMIR_THRESHOLD)?;
    let relation_evaluations = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "pool_remainder_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&evaluation_wires),
                }),
            )?;
            match decode_limit(&public_wire(&value, "standing-pool remainder relation")?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::RelationEvaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("standing-pool proof party returned another relation type".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relations = limit_relations(&statement, &relation_evaluations)?;

    let mut seals = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut rounds = Vec::with_capacity(SIGNING_QUORUM.len());
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "pool_remainder_round1",
            json!({"job_id": hex::encode(job_id)}),
        )?;
        seals.push(
            match decode_limit(&public_wire(
                value.get("seal").ok_or_else(|| {
                    "proof party omitted standing-pool remainder seal".to_string()
                })?,
                "standing-pool remainder seal",
            )?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::Round1Seal(value),
                } if wire_job == job_id => value,
                _ => return Err("standing-pool proof party returned another seal".into()),
            },
        );
        rounds.push(
            match decode_limit(&public_wire(
                value.get("round").ok_or_else(|| {
                    "proof party omitted standing-pool remainder round one".to_string()
                })?,
                "standing-pool remainder round one",
            )?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::Round1(value),
                } if wire_job == job_id => value,
                _ => return Err("standing-pool proof party returned another first round".into()),
            },
        );
    }
    let challenge = make_limit_challenge(
        &statement,
        &rounds,
        &seals,
        &SIGNING_QUORUM,
        STANDING_POOL_REMAINDER_CONTEXT,
    )?;
    let challenge_wire = encode_limit(&LimitEnvelope {
        job_id,
        message: LimitMessage::Challenge(challenge),
    })?;
    let responses = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "pool_remainder_round2",
                json!({
                    "job_id": hex::encode(job_id),
                    "challenge": BASE64.encode(&challenge_wire),
                }),
            )?;
            match decode_limit(&public_wire(&value, "standing-pool remainder round two")?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::Round2(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("standing-pool proof party returned another second round".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let proof = assemble_limit(
        key,
        &statement,
        &relations,
        &rounds,
        &seals,
        &responses,
        &SIGNING_QUORUM,
        STANDING_POOL_REMAINDER_CONTEXT,
    )?;
    if !verify_threshold_range(
        key,
        &statement.commitment,
        &proof,
        STANDING_POOL_REMAINDER_CONTEXT,
    ) {
        return Err("public verifier rejected the standing-pool remainder proof".into());
    }
    Ok((statement.commitment, proof))
}

/// Assemble every confidential settlement proof and its 3-of-7 zkPI
/// authorization from the same node-local MPC persistence used by the quote
/// proof.  The coordinator sees only public commitments and proof messages.
pub fn prove_product_settlement<T: ProofPartyRpc>(
    parties: &mut [T],
    frost_public: &frost::keys::PublicKeyPackage,
    request: ProductSettlementRequest,
) -> Result<ProductSettlementProof, String> {
    if parties.len() != COMMITTEE_SIZE {
        return Err("product settlement proof requires exactly seven parties".into());
    }
    let quote_digest = request.validate()?;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds {
        amount_bits: PRODUCT_ZKPI_AMOUNT_BITS,
        price_bits: PRODUCT_ZKPI_PRICE_BITS,
        max_horizon: 3_600,
    };

    let maker_handle_evaluations = parties
        .iter_mut()
        .map(|party| {
            party.call(
                "maker_handle_evaluation",
                json!({"job_id": hex::encode(request.job_id)}),
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut maker_handle_points = BTreeMap::new();
    for evaluation in &maker_handle_evaluations {
        let party = evaluation
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| "winning Maker handle evaluation has an invalid party".to_string())?;
        let encoded: [u8; 32] = hex::decode(
            evaluation
                .get("point")
                .and_then(Value::as_str)
                .ok_or_else(|| "winning Maker handle evaluation omitted its point".to_string())?,
        )
        .map_err(|_| "winning Maker handle evaluation is not hexadecimal")?
        .try_into()
        .map_err(|_| "winning Maker handle evaluation is not 32 bytes")?;
        let point = CompressedRistretto(encoded)
            .decompress()
            .ok_or_else(|| "winning Maker handle evaluation is not canonical".to_string())?;
        if !(1..=parties.len()).contains(&party)
            || maker_handle_points.insert(party, point).is_some()
        {
            return Err("winning Maker handle evaluation duplicated a committee party".into());
        }
    }
    let maker_handle =
        coefficient_commitments_from_evaluations(&maker_handle_points, SHAMIR_THRESHOLD)?
            .first()
            .copied()
            .ok_or_else(|| "winning Maker handle coefficient ladder is empty".to_string())?;
    if maker_handle == RistrettoPoint::default() || maker_handle == request.taker_handle {
        return Err("winning Maker and Taker handles must be distinct non-identity points".into());
    }

    let zkpi_evaluation_wires = parties
        .iter_mut()
        .map(|party| {
            party
                .call(
                    "zkpi_evaluations",
                    json!({"job_id": hex::encode(request.job_id)}),
                )
                .and_then(|value| public_wire(&value, "zkPI evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_evaluations = zkpi_evaluation_wires
        .iter()
        .map(
            |raw| match decode_zkpi(raw).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id,
                    message: ZkpiMessage::Evaluations(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("zkPI proof party returned another evaluation type".into()),
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_statements = zkpi_statements(&zkpi_evaluations, SHAMIR_THRESHOLD)?;
    let zkpi_relations = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "zkpi_bind",
                json!({
                    "job_id": hex::encode(request.job_id),
                    "evaluations": wire_array(&zkpi_evaluation_wires),
                    "maker_handle_evaluations": maker_handle_evaluations.clone(),
                }),
            )?;
            match decode_zkpi(&public_wire(&value, "zkPI relation")?)
                .map_err(|error| error.to_string())?
            {
                ZkpiEnvelope {
                    job_id,
                    message: ZkpiMessage::RelationEvaluations(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("zkPI proof party returned another relation type".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_relation_statements = zkpi_relation_statements(&zkpi_statements, &zkpi_relations)?;
    let mut zkpi_seals = Vec::new();
    let mut zkpi_round1 = Vec::new();
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "zkpi_round1",
            json!({"job_id": hex::encode(request.job_id)}),
        )?;
        let seal = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "proof party omitted zkPI round-one seal".to_string())?,
            "zkPI round-one seal",
        )?;
        let round = public_wire(
            value
                .get("round")
                .ok_or_else(|| "proof party omitted zkPI round one".to_string())?,
            "zkPI round one",
        )?;
        zkpi_seals.push(
            match decode_zkpi(&seal).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id,
                    message: ZkpiMessage::Round1Seal(value),
                } if job_id == request.job_id => value,
                _ => return Err("zkPI proof party returned another round-one seal".into()),
            },
        );
        zkpi_round1.push(
            match decode_zkpi(&round).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id,
                    message: ZkpiMessage::Round1(value),
                } if job_id == request.job_id => value,
                _ => return Err("zkPI proof party returned another round-one message".into()),
            },
        );
    }
    let zkpi_challenge =
        make_zkpi_challenge(&zkpi_statements, &zkpi_round1, &zkpi_seals, &SIGNING_QUORUM)?;
    let zkpi_challenge = match cross_zkpi(request.job_id, ZkpiMessage::Challenge(zkpi_challenge))? {
        ZkpiMessage::Challenge(value) => value,
        _ => return Err("zkPI wire changed the challenge type".into()),
    };
    let zkpi_challenge_wire = encode_zkpi(&ZkpiEnvelope {
        job_id: request.job_id,
        message: ZkpiMessage::Challenge(zkpi_challenge),
    })
    .map_err(|error| error.to_string())?;
    let zkpi_round2 = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "zkpi_round2",
                json!({
                    "job_id": hex::encode(request.job_id),
                    "challenge": BASE64.encode(&zkpi_challenge_wire),
                }),
            )?;
            match decode_zkpi(&public_wire(&value, "zkPI round two")?)
                .map_err(|error| error.to_string())?
            {
                ZkpiEnvelope {
                    job_id,
                    message: ZkpiMessage::Round2(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("zkPI proof party returned another round-two message".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_proofs = assemble_ranges(
        &key,
        &zkpi_statements,
        &zkpi_relation_statements,
        &zkpi_round1,
        &zkpi_seals,
        &zkpi_round2,
        &SIGNING_QUORUM,
    )?;
    let amount_range_wire = encode_threshold_range(&zkpi_proofs.amount)?;
    let price_range_wire = encode_threshold_range(&zkpi_proofs.price)?;
    let asset_blinding = Scalar::random(&mut OsRng);
    let asset_commitment = key.commit(&asset_scalar(&request.asset_id), &asset_blinding);
    let (cash_payer, cash_payee) = match request.limit_direction {
        PriceLimitDirection::MaximumBuyPrice => (request.taker_handle, maker_handle),
        PriceLimitDirection::MinimumSellPrice => (maker_handle, request.taker_handle),
    };
    let partial = build_partial_instruction(
        &key,
        &bounds,
        &zkpi_statements,
        zkpi_proofs,
        asset_commitment,
        cash_payer,
        cash_payee,
        request.deadline,
        request.job_id,
        quote_digest,
    )?;
    authorize_zkpi(
        parties,
        request.job_id,
        &partial,
        &amount_range_wire,
        &price_range_wire,
    )?;
    let signature =
        distributed_frost_sign(parties, &SIGNING_QUORUM, &partial.digest(), frost_public)?;
    let instruction = partial.sealed(signature);
    Venue::new(key.clone(), &bounds, frost_public.clone())
        .require_threshold_ranges()
        .verify(&instruction, request.now)
        .map_err(str::to_string)?;

    let limit_evaluation_wires = parties
        .iter_mut()
        .map(|party| {
            party
                .call(
                    "limit_evaluations",
                    json!({"job_id": hex::encode(request.job_id)}),
                )
                .and_then(|value| public_wire(&value, "hidden-limit evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let limit_evaluations = limit_evaluation_wires
        .iter()
        .map(|raw| match decode_limit(raw)? {
            LimitEnvelope {
                job_id,
                message: LimitMessage::Evaluations(value),
            } if job_id == request.job_id => Ok(value),
            _ => Err("hidden-limit proof party returned another evaluation type".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let limit_statement = limit_statement(&limit_evaluations, SHAMIR_THRESHOLD)?;
    let expected_difference = match request.limit_direction {
        PriceLimitDirection::MaximumBuyPrice => {
            request.limit_commitment - instruction.price_commitment
        }
        PriceLimitDirection::MinimumSellPrice => {
            instruction.price_commitment - request.limit_commitment
        }
    };
    if limit_statement.commitment.compress() != expected_difference.compress() {
        return Err("MPC hidden-limit witness does not match quote and signed limit".into());
    }
    let limit_relation_evaluations = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "limit_bind",
                json!({
                    "job_id": hex::encode(request.job_id),
                    "evaluations": wire_array(&limit_evaluation_wires),
                }),
            )?;
            match decode_limit(&public_wire(&value, "hidden-limit relation")?)? {
                LimitEnvelope {
                    job_id,
                    message: LimitMessage::RelationEvaluations(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("hidden-limit proof party returned another relation type".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let limit_relations = limit_relations(&limit_statement, &limit_relation_evaluations)?;
    let bound_limit_context = price_limit_context(
        request.limit_direction,
        PRODUCT_ZKPI_PRICE_BITS,
        &instruction.price_commitment,
        &request.limit_commitment,
        &request.limit_context,
    );
    let mut limit_seals = Vec::new();
    let mut limit_round1 = Vec::new();
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "limit_round1",
            json!({
                "job_id": hex::encode(request.job_id),
                "context": hex::encode(bound_limit_context),
            }),
        )?;
        limit_seals.push(
            match decode_limit(&public_wire(
                value
                    .get("seal")
                    .ok_or_else(|| "proof party omitted hidden-limit seal".to_string())?,
                "hidden-limit seal",
            )?)? {
                LimitEnvelope {
                    job_id,
                    message: LimitMessage::Round1Seal(value),
                } if job_id == request.job_id => value,
                _ => return Err("hidden-limit proof party returned another seal".into()),
            },
        );
        limit_round1.push(
            match decode_limit(&public_wire(
                value
                    .get("round")
                    .ok_or_else(|| "proof party omitted hidden-limit round one".to_string())?,
                "hidden-limit round one",
            )?)? {
                LimitEnvelope {
                    job_id,
                    message: LimitMessage::Round1(value),
                } if job_id == request.job_id => value,
                _ => return Err("hidden-limit proof party returned another first round".into()),
            },
        );
    }
    let limit_challenge = make_limit_challenge(
        &limit_statement,
        &limit_round1,
        &limit_seals,
        &SIGNING_QUORUM,
        &bound_limit_context,
    )?;
    let limit_challenge_wire = encode_limit(&LimitEnvelope {
        job_id: request.job_id,
        message: LimitMessage::Challenge(limit_challenge),
    })?;
    let limit_round2 = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "limit_round2",
                json!({
                    "job_id": hex::encode(request.job_id),
                    "challenge": BASE64.encode(&limit_challenge_wire),
                }),
            )?;
            match decode_limit(&public_wire(&value, "hidden-limit round two")?)? {
                LimitEnvelope {
                    job_id,
                    message: LimitMessage::Round2(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("hidden-limit proof party returned another second round".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let price_limit_proof = assemble_limit(
        &key,
        &limit_statement,
        &limit_relations,
        &limit_round1,
        &limit_seals,
        &limit_round2,
        &SIGNING_QUORUM,
        &bound_limit_context,
    )?;
    threshold_price_limit(
        &key,
        &instruction.price_commitment,
        &request.limit_commitment,
        request.limit_direction,
        PRODUCT_ZKPI_PRICE_BITS,
        &request.limit_context,
        price_limit_proof.clone(),
    )?;

    let dvp_evaluation_wires = parties
        .iter_mut()
        .map(|party| {
            party
                .call(
                    "dvp_evaluations",
                    json!({"job_id": hex::encode(request.job_id)}),
                )
                .and_then(|value| public_wire(&value, "DvP evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let dvp_evaluations = dvp_evaluation_wires
        .iter()
        .map(
            |raw| match decode_dvp(raw).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id,
                    message: DvpMessage::Evaluations(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("DvP proof party returned another evaluation type".into()),
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let constant = |values: BTreeMap<usize, RistrettoPoint>| -> Result<RistrettoPoint, String> {
        coefficient_commitments_from_evaluations(&values, SHAMIR_THRESHOLD).and_then(|ladder| {
            ladder
                .first()
                .copied()
                .ok_or_else(|| "empty VSS ladder".into())
        })
    };
    let cash_commitment = constant(
        dvp_evaluations
            .iter()
            .map(|node| (node.party, node.product.relation))
            .collect(),
    )?;
    let securities_remainder = constant(
        dvp_evaluations
            .iter()
            .map(|node| (node.party, node.securities_remainder.value))
            .collect(),
    )?;
    let cash_remainder = constant(
        dvp_evaluations
            .iter()
            .map(|node| (node.party, node.cash_remainder.value))
            .collect(),
    )?;
    let dvp_statements = dvp_statements(
        &instruction.amount_commitment,
        &instruction.price_commitment,
        &cash_commitment,
        &securities_remainder,
        &cash_remainder,
        &dvp_evaluations,
        SHAMIR_THRESHOLD,
    )?;
    let dvp_relations = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "dvp_bind",
                json!({
                    "job_id": hex::encode(request.job_id),
                    "evaluations": wire_array(&dvp_evaluation_wires),
                }),
            )?;
            match decode_dvp(&public_wire(&value, "DvP relation")?)
                .map_err(|error| error.to_string())?
            {
                DvpEnvelope {
                    job_id,
                    message: DvpMessage::RelationEvaluations(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("DvP proof party returned another relation type".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let dvp_relation_statements = dvp_relation_statements(&dvp_statements, &dvp_relations)?;
    let mut dvp_seals = Vec::new();
    let mut dvp_round1 = Vec::new();
    for party in SIGNING_QUORUM {
        let value = parties[party - 1]
            .call("dvp_round1", json!({"job_id": hex::encode(request.job_id)}))?;
        let seal = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "proof party omitted DvP round-one seal".to_string())?,
            "DvP round-one seal",
        )?;
        let round = public_wire(
            value
                .get("round")
                .ok_or_else(|| "proof party omitted DvP round one".to_string())?,
            "DvP round one",
        )?;
        dvp_seals.push(
            match decode_dvp(&seal).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id,
                    message: DvpMessage::Round1Seal(value),
                } if job_id == request.job_id => value,
                _ => return Err("DvP proof party returned another round-one seal".into()),
            },
        );
        dvp_round1.push(
            match decode_dvp(&round).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id,
                    message: DvpMessage::Round1(value),
                } if job_id == request.job_id => value,
                _ => return Err("DvP proof party returned another round-one message".into()),
            },
        );
    }
    let dvp_challenge =
        make_dvp_challenge(&dvp_statements, &dvp_round1, &dvp_seals, &SIGNING_QUORUM)?;
    let dvp_challenge = match cross_dvp(request.job_id, DvpMessage::Challenge(dvp_challenge))? {
        DvpMessage::Challenge(value) => value,
        _ => return Err("DvP wire changed the challenge type".into()),
    };
    let dvp_challenge_wire = encode_dvp(&DvpEnvelope {
        job_id: request.job_id,
        message: DvpMessage::Challenge(dvp_challenge),
    })
    .map_err(|error| error.to_string())?;
    let dvp_round2 = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "dvp_round2",
                json!({
                    "job_id": hex::encode(request.job_id),
                    "challenge": BASE64.encode(&dvp_challenge_wire),
                }),
            )?;
            match decode_dvp(&public_wire(&value, "DvP round two")?)
                .map_err(|error| error.to_string())?
            {
                DvpEnvelope {
                    job_id,
                    message: DvpMessage::Round2(value),
                } if job_id == request.job_id => Ok(value),
                _ => Err("DvP proof party returned another round-two message".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let dvp_proofs = assemble_dvp_proofs(
        &key,
        &dvp_statements,
        &dvp_relation_statements,
        &dvp_round1,
        &dvp_seals,
        &dvp_round2,
        &SIGNING_QUORUM,
    )?;
    if !verify_product(
        &key,
        &mut Transcript::new(DVP_PRODUCT_CONTEXT),
        &instruction.amount_commitment,
        &instruction.price_commitment,
        &cash_commitment,
        &dvp_proofs.product,
    ) || !verify_threshold_range(
        &key,
        &securities_remainder,
        &dvp_proofs.securities_remainder,
        DVP_SECURITIES_REMAINDER_CONTEXT,
    ) || !verify_threshold_range(
        &key,
        &cash_remainder,
        &dvp_proofs.cash_remainder,
        DVP_CASH_REMAINDER_CONTEXT,
    ) {
        return Err("public DvP verifier rejected the node-local MPC handoff".into());
    }

    let (maker_pool_remainder, maker_pool_remainder_proof) =
        prove_standing_pool_remainder(parties, &key, request.job_id)?;

    let securities_delivery_opening = collect_opening(
        parties,
        request.job_id,
        "securities_delivery",
        instruction.payer_handle,
    )?;
    let securities_refund_opening = collect_opening(
        parties,
        request.job_id,
        "securities_refund",
        instruction.payee_handle,
    )?;
    let cash_delivery_opening = collect_opening(
        parties,
        request.job_id,
        "cash_delivery",
        instruction.payee_handle,
    )?;
    let cash_refund_opening = collect_opening(
        parties,
        request.job_id,
        "cash_refund",
        instruction.payer_handle,
    )?;
    let mut execution_attestations = Vec::with_capacity(COMMITTEE_SIZE);
    let mut execution_node_keys = Vec::with_capacity(COMMITTEE_SIZE);
    for (node, (party, execution)) in parties.iter_mut().zip(&request.execution.nodes).enumerate() {
        let value = party.call(
            "sign_execution_attestation",
            json!({
                "job_id": hex::encode(request.job_id),
                "slot": request.execution.slot,
                "lane": request.execution.lane,
                "state_generation": request.execution.generation,
                "frame_count": request.execution.frame_count,
                "input_count": request.execution.input_count,
                "batch_digest": hex::encode(execution.batch_digest),
                "source_digest": hex::encode(execution.source_digest),
                "stdout_digest": hex::encode(execution.stdout_digest),
                "stderr_digest": hex::encode(execution.stderr_digest),
            }),
        )?;
        let public: [u8; 32] = hex::decode(
            value
                .get("identity_public")
                .and_then(Value::as_str)
                .ok_or_else(|| "proof party omitted its execution identity".to_string())?,
        )
        .map_err(|_| "proof-party execution identity is not hexadecimal")?
        .try_into()
        .map_err(|_| "proof-party execution identity is not 32 bytes")?;
        let key = VerifyingKey::from_bytes(&public)
            .map_err(|_| "proof-party execution identity is not Ed25519")?;
        let raw = BASE64
            .decode(
                value
                    .get("wire")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "proof party omitted its execution attestation".to_string())?,
            )
            .map_err(|_| "proof-party execution attestation is not base64")?;
        let decoded = decode_node_execution_attestation(&raw)?;
        let mut mismatches = Vec::new();
        if usize::from(decoded.node) != node {
            mismatches.push("node");
        }
        if decoded.slot != request.execution.slot {
            mismatches.push("slot");
        }
        if usize::try_from(decoded.lane).ok() != Some(request.execution.lane) {
            mismatches.push("lane");
        }
        if decoded.state_generation != request.execution.generation {
            mismatches.push("generation");
        }
        if decoded.frame_count != request.execution.frame_count {
            mismatches.push("frame_count");
        }
        if decoded.input_count != request.execution.input_count {
            mismatches.push("input_count");
        }
        if decoded.batch_digest != execution.batch_digest {
            mismatches.push("batch_digest");
        }
        if decoded.source_digest != execution.source_digest {
            mismatches.push("source_digest");
        }
        if decoded.stdout_digest != execution.stdout_digest {
            mismatches.push("stdout_digest");
        }
        if decoded.stderr_digest != execution.stderr_digest {
            mismatches.push("stderr_digest");
        }
        if decoded.persistence_digest != execution.persistence_digest {
            mismatches.push("persistence_digest");
        }
        if !decoded.verify(&key) {
            mismatches.push("signature");
        }
        if !mismatches.is_empty() {
            return Err(format!(
                "proof party {node} returned an execution attestation with mismatched fields: {}",
                mismatches.join(", ")
            ));
        }
        execution_node_keys.push(public);
        execution_attestations.push(decoded);
    }
    let trusted_execution_keys = execution_node_keys
        .iter()
        .map(|key| {
            VerifyingKey::from_bytes(key)
                .map_err(|_| "proof-party execution identity is not Ed25519".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let certified_execution = verify_execution_lane(
        &execution_attestations,
        &trusted_execution_keys,
        request.execution.order_digest,
    )?;
    let certified_job_id = live_proof_job_id(
        u32::try_from(certified_execution.slot)
            .map_err(|_| "execution receipt slot is outside the MPC range".to_string())?,
        usize::try_from(certified_execution.lane)
            .map_err(|_| "execution receipt lane exceeds usize".to_string())?,
        certified_execution.digest,
    )?;
    if certified_job_id != request.job_id {
        return Err("signed MPC execution receipts derive another proof job".into());
    }
    let handoff = SettlementHandoff {
        job_id: request.job_id,
        lane: request.execution.lane,
        admission_sequence: request.admission_sequence,
        admission_ticket_id: request.admission_ticket_id,
        instruction: instruction.clone(),
        frost_public: frost_public.clone(),
        quote_digest,
        quote_verification: request.quote_verification,
        limit_direction: request.limit_direction,
        limit_commitment: request.limit_commitment,
        limit_context: request.limit_context,
        price_limit_proof,
        dvp_proofs,
        cash_commitment,
        securities_remainder,
        cash_remainder,
        securities_reserve: instruction.amount_commitment + securities_remainder,
        cash_reserve: cash_commitment + cash_remainder,
        maker_pool_remainder,
        maker_pool_remainder_proof,
        securities_delivery_opening,
        securities_refund_opening,
        cash_delivery_opening,
        cash_refund_opening,
        asset_id: request.asset_id,
        asset_blinding,
        execution_context: None,
        typed_authorization: None,
    };
    Ok(ProductSettlementProof {
        handoff,
        execution_attestations: encode_execution_attestations(&execution_attestations)?,
        execution_node_keys,
    })
}

#[cfg(test)]
mod completion_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[derive(Default)]
    struct RecordingParty {
        operations: Vec<String>,
    }

    impl ProofPartyRpc for RecordingParty {
        fn call(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            self.operations.push(method.to_string());
            match method {
                "complete" => Ok(json!({"completed": true})),
                "complete_observer" => Ok(json!({"observer_completed": true})),
                _ => Err(format!("unexpected operation {method}")),
            }
        }
    }

    #[test]
    fn completion_consumes_proofs_only_on_the_configured_three_of_seven_quorum() {
        let mut parties = (0..COMMITTEE_SIZE)
            .map(|_| RecordingParty::default())
            .collect::<Vec<_>>();
        complete_product_proof(&mut parties, [9; 32]).unwrap();
        for (index, party) in parties.iter().enumerate() {
            let expected = if SIGNING_QUORUM.contains(&(index + 1)) {
                "complete"
            } else {
                "complete_observer"
            };
            assert_eq!(party.operations, [expected]);
        }
    }

    #[test]
    fn planned_job_id_matches_the_seven_signed_execution_receipts() {
        let execution = ProductExecutionRequest {
            lane: 3,
            slot: 17,
            generation: 2,
            frame_count: 1,
            input_count: 49,
            order_digest: [91; 32],
            nodes: (0..COMMITTEE_SIZE)
                .map(|node| ExecutionAttestationInput {
                    batch_digest: [u8::try_from(node + 1).unwrap(); 32],
                    source_digest: [73; 32],
                    stdout_digest: [u8::try_from(node + 11).unwrap(); 32],
                    stderr_digest: [u8::try_from(node + 21).unwrap(); 32],
                    persistence_digest: [u8::try_from(node + 31).unwrap(); 32],
                })
                .collect(),
        };
        let planned = execution.job_id().unwrap();
        let signing = (0..COMMITTEE_SIZE)
            .map(|node| SigningKey::from_bytes(&[u8::try_from(node + 1).unwrap(); 32]))
            .collect::<Vec<_>>();
        let signed = execution
            .receipt_statements()
            .unwrap()
            .into_iter()
            .zip(&signing)
            .map(|(statement, key)| statement.sign(key).unwrap())
            .collect::<Vec<_>>();
        let trusted = signing
            .iter()
            .map(SigningKey::verifying_key)
            .collect::<Vec<_>>();
        let certified = verify_execution_lane(&signed, &trusted, execution.order_digest).unwrap();
        let certified_job = live_proof_job_id(
            u32::try_from(certified.slot).unwrap(),
            usize::try_from(certified.lane).unwrap(),
            certified.digest,
        )
        .unwrap();
        assert_eq!(planned, certified_job);
    }

    #[test]
    fn job_id_changes_when_one_persistence_receipt_changes() {
        let mut execution = ProductExecutionRequest {
            lane: 0,
            slot: 1,
            generation: 1,
            frame_count: 1,
            input_count: 7,
            order_digest: [81; 32],
            nodes: (0..COMMITTEE_SIZE)
                .map(|node| ExecutionAttestationInput {
                    batch_digest: [u8::try_from(node + 1).unwrap(); 32],
                    source_digest: [71; 32],
                    stdout_digest: [u8::try_from(node + 11).unwrap(); 32],
                    stderr_digest: [u8::try_from(node + 21).unwrap(); 32],
                    persistence_digest: [u8::try_from(node + 31).unwrap(); 32],
                })
                .collect(),
        };
        let before = execution.job_id().unwrap();
        execution.nodes[4].persistence_digest[0] ^= 1;
        assert_ne!(before, execution.job_id().unwrap());
    }
}
