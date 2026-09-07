//! Real cryptographic proofs through the native VM, not mocked verification.
//! Genesis assets/facilities and committee keys are synthetic unit fixtures;
//! this is not independent-node or live Avalanche acceptance evidence.

use super::*;
use defmi::application_reservation::{
    ApplicationNoteReservation, ApplicationReserveMandate, ApplicationReserveScope,
};
use defmi::application_settlement::{
    application_fill_group, point, ApplicationFillBatchBinding, ApplicationNoteFill,
    ApplicationNoteFillBatch, ApplicationNoteRelease, ApplicationOpening, ApplicationReleaseReason,
    ApplicationSpendHead,
};
use defmi::claim_redemption::NoteClaimAuthorization;
use defmi::facility::CreditFacilityRelationProof;
use defmi::note_chain::{note_claim_recipient_commitment, ClaimAuthorizationCommitment};
use defmi::notes::{encode_spend_proof, NoteLedger, Wallet};
use qomm_proofs::opening_envelope::{encrypt_opening_share, opening_context};
use std::cell::RefCell;

const ASSETS: [[u8; 32]; 2] = [[201; 32], [202; 32]];
const FACILITIES: [[u8; 32]; 2] = [[203; 32], [204; 32]];
const HOLDS: [[u8; 32]; 2] = [[205; 32], [206; 32]];
const VIEW_SECRETS: [u64; 2] = [211, 212];

#[derive(Clone, Copy)]
struct Witness {
    values: [u64; 2],
    blindings: [Scalar; 2],
}

struct Fixture {
    state: State,
    authorizer: QuorumAuthorizer,
    key: Pedersen,
    keys: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    pq_committee: zkpi::QuorumPolicy,
    scope: ApplicationReserveScope,
    wallets: [Wallet; 2],
    claim_authorizations: RefCell<BTreeMap<[u8; 32], NoteClaimAuthorization>>,
    initial: Witness,
}

impl Fixture {
    fn new() -> Self {
        Self::with_pq_expiry(4_102_444_801)
    }

    fn with_pq_expiry(not_after: u64) -> Self {
        let (authorizer, signers) = committee();
        let (shares, public) = zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
        let mut pq_committee = zkfmi_crypto::test_support::committee(
            Sha256::digest(public.serialize().unwrap()).into(),
        );
        for member in &mut pq_committee.members {
            member.key.not_after = not_after;
        }
        let scope = ApplicationReserveScope {
            application_binding: [207; 32],
            venue_id: [208; 32],
            defmi_id: [209; 32],
            committee_key_digest: Sha256::digest(public.serialize().unwrap()).into(),
            pq_committee_digest: pq_committee.digest().unwrap(),
            committee_epoch: 1,
            amount_bits: 32,
        };
        let mut fixture = Self {
            state: State::default(),
            authorizer,
            key: Pedersen::new(b"qomm:defmi:v1"),
            keys: frost_key_packages(shares),
            public,
            pq_committee,
            scope,
            wallets: VIEW_SECRETS.map(|value| {
                Wallet::from_parts(
                    Scalar::from(value),
                    Scalar::from(value + 10),
                    zkfmi_crypto::hybrid::kem::HybridKemKey::from_seed(&[29; 96]),
                )
            }),
            claim_authorizations: RefCell::new(BTreeMap::new()),
            initial: Witness {
                values: [100, 1_000],
                blindings: [Scalar::from(41_u64), Scalar::from(42_u64)],
            },
        };
        apply(
            &mut fixture.state,
            &fixture.authorizer,
            &signers,
            "defmivm.issueApplicationReserveScope",
            "scope",
            serde_json::to_value(&fixture.scope).unwrap(),
            fixture.scope.statement().unwrap(),
            100,
        )
        .unwrap();
        for index in 0..2 {
            fixture.reserve(index, &signers);
        }
        fixture.state.validate().unwrap();
        fixture
    }

    fn reserve(
        &mut self,
        index: usize,
        signers: &BTreeMap<String, defmi::governance::GovernanceSigner>,
    ) {
        let value = self.initial.values[index];
        let blind = self.initial.blindings[index];
        let capacity_blind = Scalar::from(61 + index as u64);
        let entity = [220 + index as u8; 32];
        let asset = ASSETS[index];
        let hold_id = HOLDS[index];
        let facility_id = FACILITIES[index];
        let commit = |value, blind| self.key.commit_u64(value, &blind).compress().to_bytes();
        self.state.assets.insert(
            id_key(&asset),
            AssetRecord {
                code: if index == 0 { "SEC" } else { "JPY" }.into(),
                kind: if index == 0 { "security" } else { "cash" }.into(),
                decimals: 0,
                terms_digest: [222 + index as u8; 32],
                active: true,
            },
        );
        self.state.credit_facilities.insert(
            id_key(&facility_id),
            CreditFacilityRecord {
                guarantor_id: [224; 32],
                beneficiary_commitment: entity,
                rail_asset_id: asset,
                cap_commitment: commit(value * 2, capacity_blind),
                available_commitment: commit(value * 2, capacity_blind),
                held_commitment: ZERO,
                outstanding_commitment: ZERO,
                overlimit_commitment: ZERO,
                collateral_commitment: commit(value * 2, Scalar::from(71_u64)),
                risk_policy_digest: [225; 32],
                valid_from: 1,
                valid_until: 1_000,
                status: "active".into(),
                sequence: 0,
            },
        );
        let decoy = Wallet::new(&mut OsRng);
        let wallet = &self.wallets[index];
        let mut ledger = NoteLedger::new(self.key.clone(), 32);
        let source_blind = Scalar::from(81_u64);
        let source = ledger
            .build_note(
                &wallet.address,
                value + 10,
                self.key.commit_u64(value + 10, &source_blind),
                &source_blind,
                &mut OsRng,
            )
            .expect("valid fixture note encryption");
        let other = ledger
            .build_note(
                &decoy.address,
                25,
                self.key.commit_u64(25, &source_blind),
                &source_blind,
                &mut OsRng,
            )
            .expect("valid fixture note encryption");
        ledger.add(source);
        ledger.add(other);
        for note in &ledger.notes {
            insert_note(
                &mut self.state,
                &NoteOutput::from_note(note, asset, ZERO).unwrap(),
            )
            .unwrap();
        }
        let participant = zkfmi_crypto::hybrid::signature::HybridSigner::generate().unwrap();
        let mandate = ApplicationReserveMandate {
            version: 2,
            scope: self.scope.clone(),
            request_commitment: [228 + index as u8; 32],
            facility_id,
            hold_id,
            asset_id: asset,
            amount_commitment: commit(value, blind),
            participant_handle: wallet.address.view.compress().to_bytes(),
            entity_commitment: entity,
            credential_digest: [230 + index as u8; 32],
            settlement_terms_commitment: commit(1, Scalar::from(91_u64)),
            valid_from: 100,
            valid_until: 900,
            participant_public: zkfmi_crypto::traits::Signer::public_key(&participant),
            signature: Vec::new(),
        }
        .sign(&participant)
        .unwrap();
        let mut transition = CreditFacilityTransition {
            operation_id: [232 + index as u8; 32],
            facility_id,
            hold_id,
            kind: CreditTransitionKind::Hold,
            query_commitment: mandate.request_commitment,
            amount_commitment: mandate.amount_commitment,
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: commit(value * 2, capacity_blind),
            after_available_commitment: commit(value, capacity_blind - blind),
            before_held_commitment: ZERO,
            after_held_commitment: mandate.amount_commitment,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: ZERO,
            before_sequence: 0,
            expires_at: mandate.valid_until,
            settlement_digest: ZERO,
            relation_proof_digest: ZERO,
        };
        let relation = CreditFacilityRelationProof::prove(
            &mut transition,
            [value, value, 0, value],
            [capacity_blind - blind, blind, Scalar::ZERO, blind],
            [0, 0],
            [Scalar::ZERO; 2],
            &mut OsRng,
        )
        .unwrap();
        let source_opening = ledger
            .scan(wallet, &self.key)
            .into_iter()
            .find_map(|(index, opening)| (index == 0).then_some(opening))
            .unwrap();
        // The participant retains the reserved note's wallet keys. An expiry
        // before any fill can return exactly this note without an online MPC.
        let spend = ledger
            .build_spend_constrained_with_blindings(
                &[0, 1],
                0,
                &source_opening,
                &self.key.g,
                &Scalar::ZERO,
                &[(wallet.address, value), (wallet.address, 10)],
                &[blind, Scalar::from(92_u64)],
                &[true, true],
                &mandate.spend_context().unwrap(),
                &mut OsRng,
            )
            .unwrap();
        let escrow = NoteReservationEscrow::from_verified(
            &ledger,
            &[0, 1],
            &spend.proof,
            &spend.notes,
            asset,
            &[ZERO; 2],
            &[hold_id, ZERO],
            &transition,
            mandate.delegation_digest().unwrap(),
            &mandate.spend_context().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        let reservation = ApplicationNoteReservation {
            binding: mandate.binding().unwrap(),
            transition,
            escrow,
            relation_proof: relation.to_bytes().unwrap(),
            spend_proof: encode_spend_proof(&spend.proof).unwrap(),
        };
        let approval = self
            .authorizer
            .approve(reservation.statement().unwrap(), self.state.root(), signers)
            .unwrap();
        let transaction = TransactionEnvelope::new("defmivm.issueApplicationNoteReservation", json!({
            "binding": reservation.binding, "transition": transition_json(&reservation.transition),
            "escrow": note_reservation_escrow_json(&reservation.escrow),
            "relationProof": BASE64.encode(&reservation.relation_proof), "spendProof": BASE64.encode(&reservation.spend_proof),
            "approval": approval_json(&approval), "expectedBeforeRoot": hex::encode(self.state.root()),
        })).unwrap().encode().unwrap();
        self.state
            .apply(&transaction, &self.authorizer, 100)
            .unwrap();
    }

    fn sign_fill(&self, fill: &mut ApplicationNoteFill) {
        fill.pq_authorization = Some(zkfmi_crypto::test_support::approve(
            &self.pq_committee,
            &fill.signing_message().unwrap(),
            100,
        ));
        fill.signature = frost_sign(&self.keys, &self.public, &fill.signing_message().unwrap())
            .serialize()
            .unwrap();
    }

    fn claim_authorization(
        &self,
        recipient_handle: [u8; 32],
        context: [u8; 32],
        asset_id: [u8; 32],
        hold_id: [u8; 32],
        kind: NoteClaimKind,
    ) -> ClaimAuthorizationCommitment {
        let recipient_commitment =
            note_claim_recipient_commitment(recipient_handle, context, asset_id, hold_id, kind)
                .unwrap();
        let authorization = NoteClaimAuthorization::generate(recipient_commitment, 100, 1_000)
            .expect("fresh claim authorization");
        let commitment = authorization.commitment().unwrap();
        assert!(self
            .claim_authorizations
            .borrow_mut()
            .insert(commitment.key_fingerprint, authorization)
            .is_none());
        commitment
    }

    fn fill(
        &self,
        prior: Witness,
        quantity: u64,
        tag: u8,
        close: [bool; 2],
    ) -> (ApplicationNoteFill, Witness) {
        let values = [quantity, quantity * 10];
        let blinds = [
            Scalar::from(101 + u64::from(tag)),
            Scalar::from(111 + u64::from(tag)),
        ];
        let deltas = [
            Scalar::from(121 + u64::from(tag)),
            Scalar::from(131 + u64::from(tag)),
        ];
        let price_blind = Scalar::from(141 + u64::from(tag));
        let asset_blind = Scalar::from(151 + u64::from(tag));
        let next = Witness {
            values: [prior.values[0] - values[0], prior.values[1] - values[1]],
            blindings: [
                prior.blindings[0] - blinds[0],
                prior.blindings[1] - blinds[1],
            ],
        };
        let amount = self.key.commit_u64(quantity, &blinds[0]);
        let cash = self.key.commit_u64(values[1], &blinds[1]);
        let asset = self.key.commit(&asset_scalar(&ASSETS[0]), &asset_blind);
        let nonce = [tag; 32];
        let result = Sha256::digest(nonce).into();
        let partial = PartialInstruction::from_threshold_ranges(
            &self.key,
            &Bounds {
                amount_bits: 32,
                price_bits: 32,
                max_horizon: 3_600,
            },
            amount,
            self.key.commit_u64(10, &price_blind),
            asset,
            threshold_range(&self.key, quantity, blinds[0], 32, AMOUNT_RANGE_CONTEXT),
            threshold_range(&self.key, 10, price_blind, 32, PRICE_RANGE_CONTEXT),
            self.wallets[1].address.view,
            self.wallets[0].address.view,
            800,
            nonce,
            result,
        )
        .unwrap();
        let signature = frost_sign(
            &self.keys,
            &self.public,
            &partial.digest_for(DEFAULT_DOMAIN),
        );
        let pq = zkfmi_crypto::test_support::approve(
            &self.pq_committee,
            &partial.digest_for(DEFAULT_DOMAIN),
            100,
        );
        let payment = partial.sealed_hybrid(signature, pq);
        let claim_authorizations = [
            self.claim_authorization(
                self.wallets[1].address.view.compress().to_bytes(),
                payment.nullifier(),
                ASSETS[0],
                HOLDS[0],
                NoteClaimKind::Delivery,
            ),
            self.claim_authorization(
                self.wallets[0].address.view.compress().to_bytes(),
                payment.nullifier(),
                ASSETS[0],
                HOLDS[0],
                NoteClaimKind::Refund,
            ),
            self.claim_authorization(
                self.wallets[0].address.view.compress().to_bytes(),
                payment.nullifier(),
                ASSETS[1],
                HOLDS[1],
                NoteClaimKind::Delivery,
            ),
            self.claim_authorization(
                self.wallets[1].address.view.compress().to_bytes(),
                payment.nullifier(),
                ASSETS[1],
                HOLDS[1],
                NoteClaimKind::Refund,
            ),
        ];
        let proofs = DvpProofs {
            product: prove_product(
                &self.key,
                &mut Transcript::new(DVP_PRODUCT_CONTEXT),
                &amount,
                &Scalar::from(quantity),
                &blinds[0],
                &Scalar::from(10_u64),
                &price_blind,
                &blinds[1],
                &mut OsRng,
            ),
            securities_remainder: threshold_range(
                &self.key,
                next.values[0],
                next.blindings[0] + deltas[0],
                32,
                DVP_SECURITIES_REMAINDER_CONTEXT,
            ),
            cash_remainder: threshold_range(
                &self.key,
                next.values[1],
                next.blindings[1] + deltas[1],
                32,
                DVP_CASH_REMAINDER_CONTEXT,
            ),
        };
        let link =
            defmi::asset_link::prove(&self.key, ASSETS[0], &asset, &asset_blind, &mut OsRng)
                .unwrap();
        let head = |index: usize| {
            let record = &self.state.application_reservations[&id_key(&HOLDS[index])];
            ApplicationSpendHead {
                hold_id: HOLDS[index],
                sequence: record.sequence,
                previous_receipt: record.head_receipt(),
                remaining_commitment: record.remaining(),
                reserve_reblinding: deltas[index].to_bytes(),
                close: close[index],
            }
        };
        let mut fill = ApplicationNoteFill {
            version: 2,
            pq_committee: self.pq_committee.clone(),
            pq_authorization: None,
            batch: None,
            scope: self.scope.clone(),
            before_root: self.state.root(),
            operation_id: [tag + 40; 32],
            mpc_result_digest: result,
            securities_asset: ASSETS[0],
            cash_asset: ASSETS[1],
            securities: head(0),
            cash: head(1),
            instruction: zkpi::wire::encode(&payment),
            dvp_proofs: encode_dvp_proofs(&proofs).unwrap(),
            cash_commitment: cash.compress().to_bytes(),
            asset_link_announcement: link.announcement.compress().to_bytes(),
            asset_link_response: link.response.to_bytes(),
            openings: [
                opening(
                    nonce,
                    "securities_delivery",
                    quantity,
                    blinds[0],
                    &self.wallets[1],
                    payment.nullifier(),
                    claim_authorizations[0],
                ),
                opening(
                    nonce,
                    "securities_refund",
                    next.values[0],
                    next.blindings[0] + deltas[0],
                    &self.wallets[0],
                    payment.nullifier(),
                    claim_authorizations[1],
                ),
                opening(
                    nonce,
                    "cash_delivery",
                    values[1],
                    blinds[1],
                    &self.wallets[0],
                    payment.nullifier(),
                    claim_authorizations[2],
                ),
                opening(
                    nonce,
                    "cash_refund",
                    next.values[1],
                    next.blindings[1] + deltas[1],
                    &self.wallets[1],
                    payment.nullifier(),
                    claim_authorizations[3],
                ),
            ],
            committee_public: self.public.serialize().unwrap(),
            signature: Vec::new(),
        };
        self.sign_fill(&mut fill);
        (fill, next)
    }

    fn release(
        &self,
        index: usize,
        reason: ApplicationReleaseReason,
        tag: u8,
    ) -> ApplicationNoteRelease {
        let record = &self.state.application_reservations[&id_key(&HOLDS[index])];
        let mut release = ApplicationNoteRelease {
            pq_committee: None,
            pq_authorization: None,
            scope: self.scope.clone(),
            before_root: self.state.root(),
            operation_id: [tag; 32],
            hold_id: HOLDS[index],
            sequence: record.sequence,
            previous_receipt: record.head_receipt(),
            reason,
            committee_public: Vec::new(),
            signature: Vec::new(),
        };
        if reason == ApplicationReleaseReason::Cancelled {
            release.committee_public = self.public.serialize().unwrap();
            release.pq_committee = Some(self.pq_committee.clone());
            release.pq_authorization = Some(zkfmi_crypto::test_support::approve(
                &self.pq_committee,
                &release.signing_message().unwrap(),
                100,
            ));
            release.signature = frost_sign(
                &self.keys,
                &self.public,
                &release.signing_message().unwrap(),
            )
            .serialize()
            .unwrap();
        }
        release
    }
}

fn opening(
    nonce: [u8; 32],
    leg: &str,
    value: u64,
    blind: Scalar,
    recipient: &Wallet,
    claim_context: [u8; 32],
    claim_authorization: ClaimAuthorizationCommitment,
) -> ApplicationOpening {
    let context = opening_context(&nonce, leg).unwrap();
    // Actual encrypted degree-two Shamir evaluations; known test-only
    // coefficients make the expected plaintext independently checkable.
    let shares = (1..=7)
        .map(|party| {
            let x = Scalar::from(party as u64);
            encrypt_opening_share(
                context,
                party,
                Scalar::from(value) + Scalar::from(7_u64) * x + Scalar::from(13_u64) * x * x,
                blind + Scalar::from(17_u64) * x + Scalar::from(19_u64) * x * x,
                &recipient.address.view,
                &recipient.address.opening_public,
                &mut OsRng,
            )
            .unwrap()
        })
        .collect();
    ApplicationOpening::from_domain(
        &OpeningEnvelope::new(context, 3, recipient.address.view, shares).unwrap(),
        claim_context,
        claim_authorization,
    )
    .unwrap()
}

fn fill_tx(fill: &ApplicationNoteFill) -> Vec<u8> {
    TransactionEnvelope::new("defmivm.issueApplicationNoteFill", json!({"fill": fill}))
        .unwrap()
        .encode()
        .unwrap()
}

fn batch_tx(batch: &ApplicationNoteFillBatch) -> Vec<u8> {
    TransactionEnvelope::new(
        "defmivm.issueApplicationNoteFillBatch",
        json!({"batch": batch}),
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn two_fill_batch(fixture: &mut Fixture) -> ApplicationNoteFillBatch {
    let initial = fixture.state.clone();
    let (mut first, remaining) = fixture.fill(fixture.initial, 40, 3, [false; 2]);
    fixture
        .state
        .apply(&fill_tx(&first), &fixture.authorizer, 200)
        .unwrap();
    let (mut second, _) = fixture.fill(remaining, 20, 4, [true; 2]);
    fixture.state = initial;
    second.before_root = first.before_root;
    let group = application_fill_group(
        &first.scope,
        first.before_root,
        &[first.operation_id, second.operation_id],
    )
    .unwrap();
    first.batch = Some(ApplicationFillBatchBinding {
        group,
        index: 0,
        count: 2,
    });
    fixture.sign_fill(&mut first);
    second.securities.previous_receipt = first.signing_message().unwrap();
    second.cash.previous_receipt = first.signing_message().unwrap();
    second.batch = Some(ApplicationFillBatchBinding {
        group,
        index: 1,
        count: 2,
    });
    fixture.sign_fill(&mut second);
    ApplicationNoteFillBatch {
        version: 1,
        fills: vec![first, second],
    }
}

#[test]
fn atomic_native_batch_updates_cumulative_holds_once_and_survives_state_reopen() {
    let mut fixture = Fixture::new();
    let batch = two_fill_batch(&mut fixture);
    assert!(batch_tx(&batch).len() <= crate::block::MAX_TRANSACTION_BYTES);
    let count = fixture.state.transition_count;
    let receipt = fixture
        .state
        .apply(&batch_tx(&batch), &fixture.authorizer, 200)
        .unwrap();
    assert_eq!(receipt.statement, batch.statement().unwrap());
    assert_eq!(fixture.state.transition_count, count + 1);
    assert_eq!(fixture.state.note_claims.len(), 6);
    for (index, hold) in HOLDS.iter().enumerate() {
        let record = &fixture.state.application_reservations[&id_key(hold)];
        assert_eq!(record.sequence, 2);
        assert_eq!(record.status, "consumed");
        let facility = &fixture.state.credit_facilities[&id_key(&FACILITIES[index])];
        assert_eq!(
            point(facility.cap_commitment).unwrap(),
            point(facility.available_commitment).unwrap()
                + point(facility.held_commitment).unwrap()
                + point(facility.outstanding_commitment).unwrap()
        );
    }
    fixture.state = restored(&fixture.state);
    let finalized = fixture.state.root();
    assert!(fixture
        .state
        .apply(&batch_tx(&batch), &fixture.authorizer, 201)
        .is_err());
    assert_eq!(fixture.state.root(), finalized);
}

#[test]
fn native_batch_rejects_extraction_omission_reorder_and_rolls_back_a_bad_second_fill() {
    let mut fixture = Fixture::new();
    let batch = two_fill_batch(&mut fixture);
    let before = serde_json::to_vec(&fixture.state).unwrap();
    for member in &batch.fills {
        assert!(fixture
            .state
            .apply(&fill_tx(member), &fixture.authorizer, 200)
            .is_err());
        let mut stripped = member.clone();
        stripped.batch = None;
        assert!(fixture
            .state
            .apply(&fill_tx(&stripped), &fixture.authorizer, 200)
            .is_err());
        assert_eq!(serde_json::to_vec(&fixture.state).unwrap(), before);
    }
    for mutation in 0..7 {
        let mut changed = batch.clone();
        match mutation {
            0 => {
                changed.fills.pop();
            }
            1 => changed.fills.reverse(),
            2 => changed.fills[1].batch.as_mut().unwrap().group[0] ^= 1,
            3 => {
                changed.fills[1].dvp_proofs[0] ^= 1;
                fixture.sign_fill(&mut changed.fills[1]);
            }
            4 => {
                changed.fills[1].cash.remaining_commitment =
                    changed.fills[0].cash.remaining_commitment;
                fixture.sign_fill(&mut changed.fills[1]);
            }
            5 => {
                changed.fills[1].cash.previous_receipt = [17; 32];
                fixture.sign_fill(&mut changed.fills[1]);
            }
            6 => changed.fills[1].signature[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            fixture
                .state
                .apply(&batch_tx(&changed), &fixture.authorizer, 200)
                .is_err(),
            "accepted batch mutation {mutation}"
        );
        assert_eq!(
            serde_json::to_vec(&fixture.state).unwrap(),
            before,
            "partial state survived mutation {mutation}"
        );
    }
}

fn release_tx(release: &ApplicationNoteRelease) -> Vec<u8> {
    TransactionEnvelope::new(
        "defmivm.issueApplicationNoteRelease",
        json!({"release": release}),
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn restored(state: &State) -> State {
    let bytes = serde_json::to_vec(state).unwrap();
    let restored: State = serde_json::from_slice(&bytes).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.root(), state.root());
    restored
}

#[test]
fn successive_partial_fills_keep_only_remainders_locked_and_recover_after_restart() {
    let mut fixture = Fixture::new();
    let initial_serials = fixture.state.note_serials.len();
    let (first, remaining) = fixture.fill(fixture.initial, 40, 1, [false; 2]);
    let receipt = fixture
        .state
        .apply(&fill_tx(&first), &fixture.authorizer, 200)
        .unwrap();
    assert_eq!(receipt.statement, first.signing_message().unwrap());
    assert_eq!(fixture.state.note_claims.len(), 2);
    assert_eq!(fixture.state.note_serials.len(), initial_serials + 2);
    assert!(fixture.state.accounts.is_empty());
    for index in 0..2 {
        let record = &fixture.state.application_reservations[&id_key(&HOLDS[index])];
        assert_eq!(record.sequence, 1);
        assert_eq!(record.status, "active");
        let encrypted = record.remaining_opening.as_ref().unwrap().domain().unwrap();
        for quorum in [[1, 4, 7], [2, 3, 6]] {
            let (value, blind) = encrypted
                .decrypt(
                    &Scalar::from(VIEW_SECRETS[index]),
                    fixture.wallets[index].opening_key(),
                    &quorum,
                )
                .unwrap();
            assert_eq!(value, Scalar::from(remaining.values[index]));
            assert_eq!(blind, remaining.blindings[index]);
            assert_eq!(
                fixture.key.commit(&value, &blind).compress().to_bytes(),
                record.remaining()
            );
        }
        let facility = &fixture.state.credit_facilities[&id_key(&FACILITIES[index])];
        assert_eq!(facility.held_commitment, record.remaining());
        assert_eq!(
            point(facility.cap_commitment).unwrap(),
            point(facility.available_commitment).unwrap()
                + point(facility.held_commitment).unwrap()
                + point(facility.outstanding_commitment).unwrap()
        );
    }
    fixture.state = restored(&fixture.state);
    for mutation in 0..5 {
        let mut damaged = fixture.state.clone();
        let record = damaged
            .application_reservations
            .get_mut(&id_key(&HOLDS[0]))
            .unwrap();
        match mutation {
            0 => record.remaining_opening = None,
            1 => record.remaining_commitment = Some(ZERO),
            2 => record.last_receipt = Some([250; 32]),
            3 => {
                damaged.note_serials.remove(&id_key(&escrow_claim_serial(
                    record.escrow_note_id,
                    HOLDS[0],
                )));
            }
            4 => {
                record.sequence = 0;
            }
            _ => unreachable!(),
        }
        assert!(
            damaged.validate().is_err(),
            "accepted incomplete recovered head {mutation}"
        );
    }
    let after_first = fixture.state.root();
    assert!(fixture
        .state
        .apply(&fill_tx(&first), &fixture.authorizer, 201)
        .is_err());
    assert_eq!(fixture.state.root(), after_first);
    let (second, final_remaining) = fixture.fill(remaining, 20, 2, [true; 2]);
    fixture
        .state
        .apply(&fill_tx(&second), &fixture.authorizer, 202)
        .unwrap();
    assert_eq!(fixture.state.note_claims.len(), 6);
    assert_eq!(fixture.state.note_serials.len(), initial_serials + 2);
    for index in 0..2 {
        let record = &fixture.state.application_reservations[&id_key(&HOLDS[index])];
        assert_eq!(record.sequence, 2);
        assert_eq!(record.status, "consumed");
        assert!(record.remaining_opening.is_none());
        assert_eq!(
            record.remaining(),
            fixture
                .key
                .commit_u64(
                    final_remaining.values[index],
                    &final_remaining.blindings[index]
                )
                .compress()
                .to_bytes()
        );
        let facility = &fixture.state.credit_facilities[&id_key(&FACILITIES[index])];
        assert_eq!(facility.held_commitment, ZERO);
        assert_eq!(
            point(facility.cap_commitment).unwrap(),
            point(facility.available_commitment).unwrap()
                + point(facility.outstanding_commitment).unwrap()
        );
    }
    restored(&fixture.state);
}

#[test]
fn unsigned_candidate_verification_never_authorizes_native_execution() {
    let mut fixture = Fixture::new();
    let (signed, _) = fixture.fill(fixture.initial, 40, 3, [false; 2]);
    assert!(signed.verify_unsigned(&fixture.scope, 200).is_err());
    let mut candidate = signed.clone();
    candidate.signature.clear();
    candidate.pq_authorization = None;
    candidate.verify_unsigned(&fixture.scope, 200).unwrap();
    assert!(candidate.verify(&fixture.scope, 200).is_err());
    let before = fixture.state.root();
    assert!(fixture
        .state
        .apply(&fill_tx(&candidate), &fixture.authorizer, 200)
        .is_err());
    assert_eq!(fixture.state.root(), before);
    let mut bad = candidate.clone();
    bad.dvp_proofs[80] ^= 1;
    assert!(bad.verify_unsigned(&fixture.scope, 200).is_err());
    let mut rebound_claim = candidate.clone();
    rebound_claim.openings[1].claim_context = [244; 32];
    assert!(rebound_claim.verify_unsigned(&fixture.scope, 200).is_err());
    let mut legacy = serde_json::to_value(&candidate).unwrap();
    legacy["openings"][0]
        .as_object_mut()
        .unwrap()
        .remove("claimContext");
    assert!(serde_json::from_value::<ApplicationNoteFill>(legacy).is_err());
    let mut other_scope = fixture.scope.clone();
    other_scope.committee_epoch += 1;
    assert!(candidate.verify_unsigned(&other_scope, 200).is_err());
    fixture
        .state
        .apply(&fill_tx(&signed), &fixture.authorizer, 200)
        .unwrap();
}

#[test]
fn native_monetary_and_head_checks_reject_even_freshly_committee_signed_forgery() {
    let mut fixture = Fixture::new();
    let (first, _) = fixture.fill(fixture.initial, 40, 3, [false; 2]);
    let before = fixture.state.root();
    // Except the last case, replace the committee certificate too. This
    // distinguishes native verification from signature-only authorization.
    for mutation in 0..10 {
        let mut bad = first.clone();
        match mutation {
            0 => bad.dvp_proofs[80] ^= 1,
            1 => bad.securities.reserve_reblinding = Scalar::from(999_u64).to_bytes(),
            2 => {
                bad.cash_commitment = fixture
                    .key
                    .commit_u64(401, &Scalar::ONE)
                    .compress()
                    .to_bytes()
            }
            3 => bad.asset_link_response = Scalar::ONE.to_bytes(),
            4 => bad.mpc_result_digest = [240; 32],
            5 => bad.securities.sequence = 1,
            6 => bad.cash.previous_receipt = [241; 32],
            7 => {
                bad.cash.remaining_commitment = fixture
                    .key
                    .commit_u64(2_000, &Scalar::ONE)
                    .compress()
                    .to_bytes()
            }
            8 => bad.openings[0].context = [242; 32],
            9 => {
                bad.securities.close = true;
            }
            _ => unreachable!(),
        }
        if mutation != 9 {
            fixture.sign_fill(&mut bad);
        }
        assert!(
            fixture
                .state
                .apply(&fill_tx(&bad), &fixture.authorizer, 200)
                .is_err(),
            "accepted signed mutation {mutation}"
        );
        assert_eq!(fixture.state.root(), before);
    }
    let (_, other_key) = zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
    let mut wrong_committee = first.clone();
    wrong_committee.committee_public = other_key.serialize().unwrap();
    assert!(fixture
        .state
        .apply(&fill_tx(&wrong_committee), &fixture.authorizer, 200)
        .is_err());
    assert!(fixture
        .state
        .apply(&fill_tx(&first), &fixture.authorizer, 901)
        .is_err());
    assert_eq!(fixture.state.root(), before);
    fixture
        .state
        .apply(&fill_tx(&first), &fixture.authorizer, 200)
        .unwrap();
    let after = fixture.state.root();
    let mut stale = first;
    stale.before_root = after;
    stale.operation_id = [243; 32];
    fixture.sign_fill(&mut stale);
    assert!(fixture
        .state
        .apply(&fill_tx(&stale), &fixture.authorizer, 201)
        .is_err());
    assert_eq!(fixture.state.root(), after);
}

#[test]
fn public_expiry_returns_unfilled_note_to_original_wallet_without_signatures() {
    let mut fixture = Fixture::new();
    let release = fixture.release(0, ApplicationReleaseReason::Expired, 20);
    assert!(release.signature.is_empty() && release.committee_public.is_empty());
    let root = fixture.state.root();
    assert!(fixture
        .state
        .apply(&release_tx(&release), &fixture.authorizer, 900)
        .is_err());
    assert_eq!(fixture.state.root(), root);
    // A suspended facility must not trap the owner's refund.
    fixture
        .state
        .credit_facilities
        .get_mut(&id_key(&FACILITIES[0]))
        .unwrap()
        .status = "suspended".into();
    let release = fixture.release(0, ApplicationReleaseReason::Expired, 20);
    let record = fixture.state.application_reservations[&id_key(&HOLDS[0])].clone();
    let mut expected =
        fixture.state.notes[&id_key(&record.escrow_note_id)].output(record.escrow_note_id);
    expected.lock_id = ZERO;
    expected.note_id = expected.derived_id().unwrap();
    fixture
        .state
        .apply(&release_tx(&release), &fixture.authorizer, 901)
        .unwrap();
    assert_eq!(
        fixture.state.notes[&id_key(&expected.note_id)].output(expected.note_id),
        expected
    );
    assert!(fixture.state.note_claims.is_empty());
    let mut wallet_ledger = NoteLedger::new(fixture.key.clone(), 32);
    wallet_ledger.add(expected.to_note().unwrap());
    let openings = wallet_ledger.scan(&fixture.wallets[0], &fixture.key);
    assert_eq!(openings.len(), 1);
    // Opening commitment recovery proves that simply clearing the lock did
    // not replace the recipient or damage its ciphertext.
    assert_eq!(
        wallet_ledger.notes[0].value_commitment,
        fixture
            .key
            .commit_u64(fixture.initial.values[0], &fixture.initial.blindings[0])
    );
    assert_eq!(
        fixture.state.credit_facilities[&id_key(&FACILITIES[0])].held_commitment,
        ZERO
    );
    let after = fixture.state.root();
    assert!(fixture
        .state
        .apply(&release_tx(&release), &fixture.authorizer, 902)
        .is_err());
    assert_eq!(fixture.state.root(), after);
    restored(&fixture.state);
}

#[test]
fn partial_expiry_and_ordered_cancellation_release_exact_current_head() {
    let mut fixture = Fixture::new();
    let stale_cancel = fixture.release(0, ApplicationReleaseReason::Cancelled, 21);
    let (fill, remainder) = fixture.fill(fixture.initial, 40, 4, [false; 2]);
    let fill_nullifier = fill.verify(&fixture.scope, 200).unwrap().nullifier;
    let refund_authorizations = [
        fill.openings[1].claim_authorization,
        fill.openings[3].claim_authorization,
    ];
    fixture
        .state
        .apply(&fill_tx(&fill), &fixture.authorizer, 200)
        .unwrap();
    let before = fixture.state.root();
    assert!(fixture
        .state
        .apply(&release_tx(&stale_cancel), &fixture.authorizer, 201)
        .is_err());
    assert_eq!(fixture.state.root(), before);
    for hold in HOLDS {
        assert_eq!(
            fixture.state.application_reservations[&id_key(&hold)]
                .remaining_opening
                .as_ref()
                .unwrap()
                .claim_context,
            fill_nullifier
        );
    }
    let mut legacy = serde_json::to_value(&fixture.state).unwrap();
    legacy["applicationReservations"][id_key(&HOLDS[0])]["remainingOpening"]
        .as_object_mut()
        .unwrap()
        .remove("claimContext");
    assert!(serde_json::from_value::<State>(legacy).is_err());
    let mut rebound = fixture.state.clone();
    rebound
        .application_reservations
        .get_mut(&id_key(&HOLDS[0]))
        .unwrap()
        .remaining_opening
        .as_mut()
        .unwrap()
        .claim_context = [245; 32];
    assert!(rebound.validate().is_err());
    fixture.state = restored(&fixture.state);
    let cancel = fixture.release(0, ApplicationReleaseReason::Cancelled, 22);
    let mut unsigned = cancel.clone();
    unsigned.signature.clear();
    unsigned.pq_authorization = None;
    assert!(fixture
        .state
        .apply(&release_tx(&unsigned), &fixture.authorizer, 201)
        .is_err());
    fixture
        .state
        .apply(&release_tx(&cancel), &fixture.authorizer, 201)
        .unwrap();
    let expiry = fixture.release(1, ApplicationReleaseReason::Expired, 23);
    fixture
        .state
        .apply(&release_tx(&expiry), &fixture.authorizer, 901)
        .unwrap();
    assert_eq!(fixture.state.note_claims.len(), 4);
    let release_contexts = [cancel.operation_id, expiry.operation_id];
    for index in 0..2 {
        let record = &fixture.state.application_reservations[&id_key(&HOLDS[index])];
        assert_eq!(record.status, "released");
        assert_eq!(record.sequence, 2);
        let claim = fixture
            .state
            .note_claims
            .values()
            .find(|claim| claim.source_hold_id == HOLDS[index] && claim.kind == "refund")
            .unwrap();
        let refund_opening = &fill.openings[index * 2 + 1];
        assert_eq!(claim.authorization, refund_authorizations[index]);
        assert_eq!(
            claim.recipient_commitment,
            note_claim_recipient_commitment(
                refund_opening.recipient_view,
                fill_nullifier,
                ASSETS[index],
                HOLDS[index],
                NoteClaimKind::Refund,
            )
            .unwrap()
        );
        assert_ne!(
            claim.recipient_commitment,
            note_claim_recipient_commitment(
                refund_opening.recipient_view,
                release_contexts[index],
                ASSETS[index],
                HOLDS[index],
                NoteClaimKind::Refund,
            )
            .unwrap()
        );
        let encrypted = claim.opening_envelope.domain().unwrap();
        let (value, blind) = encrypted
            .decrypt(
                &Scalar::from(VIEW_SECRETS[index]),
                fixture.wallets[index].opening_key(),
                &[1, 4, 7],
            )
            .unwrap();
        assert_eq!(value, Scalar::from(remainder.values[index]));
        assert_eq!(blind, remainder.blindings[index]);
        assert_eq!(
            fixture.key.commit(&value, &blind).compress().to_bytes(),
            claim.value_commitment
        );
        assert_eq!(
            fixture.state.credit_facilities[&id_key(&FACILITIES[index])].held_commitment,
            ZERO
        );
    }
    restored(&fixture.state);
}

/// Runs real VM execution behind the client trait. Consensus/block receipts
/// are a unit-level adapter, not a substitute for live-validator acceptance.
struct NativeClient {
    state: std::sync::Mutex<State>,
    receipts: std::sync::Mutex<BTreeMap<String, defmi::avalanche::AcceptedTransition>>,
    authorizer: QuorumAuthorizer,
    receipt_mutation: std::sync::atomic::AtomicUsize,
}

impl NativeClient {
    fn issue(&self, bytes: &[u8]) -> Result<String, String> {
        let tx = TransactionEnvelope::decode(bytes)?.id()?.to_string();
        let mut receipts = self.receipts.lock().unwrap();
        if receipts.contains_key(&tx) {
            return Ok(tx);
        }
        let mut state = self.state.lock().unwrap();
        let receipt = state.apply(bytes, &self.authorizer, 200)?;
        receipts.insert(
            tx.clone(),
            defmi::avalanche::AcceptedTransition {
                tx_id: tx.clone(),
                block_id: hex::encode(receipt.after_root),
                height: state.transition_count,
                statement: receipt.statement,
                before_root: receipt.before_root,
                after_root: receipt.after_root,
            },
        );
        Ok(tx)
    }
}

impl defmi::avalanche::AvalancheClient for NativeClient {
    fn issue_asset(
        &self,
        _: &defmi::facility::AssetDefinition,
        _: &QuorumApproval,
        _: [u8; 32],
    ) -> Result<String, String> {
        Err("asset admission is outside this application-lifecycle test client".into())
    }

    fn issue_account(
        &self,
        _: &defmi::facility::AccountOpening,
        _: &QuorumApproval,
        _: [u8; 32],
    ) -> Result<String, String> {
        Err("the application-note test must not open an account".into())
    }

    fn issue_settlement(
        &self,
        _: &defmi::facility::SettlementOrder,
        _: &QuorumApproval,
        _: [u8; 32],
    ) -> Result<String, String> {
        Err("the application-note test must not fall back to account settlement".into())
    }

    fn state_root(&self) -> Result<[u8; 32], String> {
        Err(
            "the certified-submission path must not replace its signed parent with a fresh root"
                .into(),
        )
    }

    fn issue_application_note_fill(&self, fill: &ApplicationNoteFill) -> Result<String, String> {
        self.issue(&fill_tx(fill))
    }
    fn issue_application_note_fill_batch(
        &self,
        batch: &ApplicationNoteFillBatch,
    ) -> Result<String, String> {
        self.issue(&batch_tx(batch))
    }

    fn issue_application_note_release(
        &self,
        release: &ApplicationNoteRelease,
    ) -> Result<String, String> {
        self.issue(&release_tx(release))
    }

    fn wait_accepted(
        &self,
        tx: &str,
        _timeout: std::time::Duration,
        _poll: std::time::Duration,
    ) -> Result<defmi::avalanche::AcceptedTransition, String> {
        let mut receipt = self
            .receipts
            .lock()
            .unwrap()
            .get(tx)
            .cloned()
            .ok_or("unknown transaction")?;
        match self
            .receipt_mutation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            1 => receipt.tx_id = "another-transaction".into(),
            2 => receipt.statement = [1; 32],
            3 => receipt.before_root = [2; 32],
            4 => receipt.after_root = ZERO,
            5 => receipt.after_root = receipt.before_root,
            6 => receipt.height = 0,
            7 => receipt.block_id.clear(),
            _ => {}
        }
        Ok(receipt)
    }
}

#[test]
fn application_bridge_retries_exact_certified_bytes_and_checks_finality_receipt() {
    let mut fixture = Fixture::new();
    let (fill, _) = fixture.fill(fixture.initial, 40, 5, [false; 2]);
    let client = NativeClient {
        state: std::sync::Mutex::new(fixture.state.clone()),
        receipts: std::sync::Mutex::new(BTreeMap::new()),
        authorizer: fixture.authorizer.clone(),
        receipt_mutation: std::sync::atomic::AtomicUsize::new(0),
    };
    let bridge = defmi::avalanche::AvalancheNoteBridge::new(&fixture.authorizer, &client);
    let accepted = bridge.settle_application(&fill).unwrap();
    let after = client.state.lock().unwrap().root();
    let retried = bridge.settle_application(&fill).unwrap();
    assert_eq!(accepted.tx_id, retried.tx_id);
    assert_eq!(client.state.lock().unwrap().root(), after);
    for mutation in 1..=7 {
        client
            .receipt_mutation
            .store(mutation, std::sync::atomic::Ordering::SeqCst);
        assert!(
            bridge.settle_application(&fill).is_err(),
            "accepted receipt mutation {mutation}"
        );
        assert_eq!(client.state.lock().unwrap().root(), after);
    }
    client
        .receipt_mutation
        .store(0, std::sync::atomic::Ordering::SeqCst);
    fixture.state = client.state.lock().unwrap().clone();
    let cancel = fixture.release(0, ApplicationReleaseReason::Cancelled, 24);
    let cancelled = bridge.release_application(&cancel).unwrap();
    assert_eq!(
        bridge.release_application(&cancel).unwrap().tx_id,
        cancelled.tx_id
    );
    assert_eq!(
        client.state.lock().unwrap().application_reservations[&id_key(&HOLDS[0])].status,
        "released"
    );
    restored(&client.state.lock().unwrap());
}

#[test]
fn closing_one_order_does_not_release_the_counterpartys_remaining_reserve() {
    let mut fixture = Fixture::new();
    let (fill, remainder) = fixture.fill(fixture.initial, 40, 6, [true, false]);
    fixture
        .state
        .apply(&fill_tx(&fill), &fixture.authorizer, 200)
        .unwrap();
    assert_eq!(fixture.state.note_claims.len(), 3);
    assert_eq!(
        fixture.state.application_reservations[&id_key(&HOLDS[0])].status,
        "consumed"
    );
    assert_eq!(
        fixture.state.application_reservations[&id_key(&HOLDS[1])].status,
        "active"
    );
    assert_eq!(
        fixture.state.credit_facilities[&id_key(&FACILITIES[0])].held_commitment,
        ZERO
    );
    assert_eq!(
        fixture.state.credit_facilities[&id_key(&FACILITIES[1])].held_commitment,
        fixture
            .key
            .commit_u64(remainder.values[1], &remainder.blindings[1])
            .compress()
            .to_bytes()
    );
    let expired_closed = fixture.release(0, ApplicationReleaseReason::Expired, 25);
    let before = fixture.state.root();
    assert!(fixture
        .state
        .apply(&release_tx(&expired_closed), &fixture.authorizer, 901)
        .is_err());
    assert_eq!(fixture.state.root(), before);
    let expiry = fixture.release(1, ApplicationReleaseReason::Expired, 26);
    fixture
        .state
        .apply(&release_tx(&expiry), &fixture.authorizer, 901)
        .unwrap();
    assert_eq!(fixture.state.note_claims.len(), 4);
    assert_eq!(
        fixture.state.credit_facilities[&id_key(&FACILITIES[1])].held_commitment,
        ZERO
    );
    restored(&fixture.state);
}

#[test]
fn native_recipient_redeems_final_refund_without_governance_or_destination_keys() {
    use defmi::claim_redemption::{claim_participant_id, redeem_claim};
    let mut fixture = Fixture::new();
    let (fill, remainder) = fixture.fill(fixture.initial, 40, 7, [false, true]);
    let claim = fill
        .verify(&fixture.scope, 200)
        .unwrap()
        .claims
        .into_iter()
        .find(|c| c.kind == NoteClaimKind::Refund && c.asset_id == ASSETS[1])
        .unwrap();
    fixture
        .state
        .apply(&fill_tx(&fill), &fixture.authorizer, 200)
        .unwrap();
    let destination = Wallet::new(&mut OsRng);
    let redemption = {
        let authorizations = fixture.claim_authorizations.borrow();
        redeem_claim(
            &claim,
            &fixture.key,
            32,
            &Scalar::from(VIEW_SECRETS[1]),
            fixture.wallets[1].opening_key(),
            &destination.address,
            &[1, 4, 7],
            fixture.authorizer.domain(),
            fixture.state.root(),
            [71; 32],
            &authorizations[&claim.authorization.key_fingerprint],
            201,
            &mut OsRng,
        )
        .unwrap()
    };
    assert_eq!(redemption.version, 2);
    assert_eq!(redemption.authorization_signature.len(), 64 + 3_309);
    assert_eq!(redemption.authorization_key.public_key.len(), 32 + 1_952);
    assert_eq!(
        redemption.authorization_key.participant_id,
        claim_participant_id(claim.recipient_commitment).unwrap()
    );
    let persisted = serde_json::to_vec(&redemption).unwrap();
    let restored_redemption: defmi::claim_redemption::NoteClaimRedemption =
        serde_json::from_slice(&persisted).unwrap();
    assert_eq!(serde_json::to_vec(&restored_redemption).unwrap(), persisted);
    assert_eq!(
        restored_redemption.authorization_signature,
        redemption.authorization_signature
    );
    assert_ne!(
        redemption.output.one_time,
        destination.address.view.compress().to_bytes()
    );
    assert_ne!(
        redemption.output.one_time,
        destination.address.spend.compress().to_bytes()
    );
    let tx = TransactionEnvelope::new(
        "defmivm.issueNoteClaimRedemption",
        json!({"redemption": redemption}),
    )
    .unwrap()
    .encode()
    .unwrap();
    let before = fixture.state.root();
    let receipt = fixture.state.apply(&tx, &fixture.authorizer, 201).unwrap();
    assert_eq!(receipt.before_root, before);
    assert_eq!(receipt.statement, redemption.signing_message().unwrap());
    assert_eq!(
        fixture.state.note_claims[&id_key(&claim.claim_id)].status,
        "materialized"
    );
    let output =
        fixture.state.notes[&id_key(&redemption.output.note_id)].output(redemption.output.note_id);
    assert_eq!(output, redemption.output);
    let mut ledger = NoteLedger::new(fixture.key.clone(), 32);
    ledger.add(output.to_note().unwrap());
    let notes = ledger.scan(&destination, &fixture.key);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].1.value, remainder.values[1]);
    assert_eq!(notes[0].1.blinding, remainder.blindings[1]);
    assert!(ledger.scan(&fixture.wallets[1], &fixture.key).is_empty());
    assert!(fixture.state.accounts.is_empty());
    fixture.state = restored(&fixture.state);
    let after = fixture.state.root();
    assert!(fixture.state.apply(&tx, &fixture.authorizer, 202).is_err());
    assert_eq!(after, fixture.state.root());
}

#[test]
fn claim_authorization_keys_are_fresh_per_claim_and_cannot_be_reused() {
    let mut fixture = Fixture::new();
    let (first, remaining) = fixture.fill(fixture.initial, 40, 18, [false; 2]);
    let first_claims = first.verify(&fixture.scope, 200).unwrap().claims;
    let first_fingerprints = first_claims
        .iter()
        .map(|claim| claim.authorization.key_fingerprint)
        .collect::<BTreeSet<_>>();
    assert_eq!(first_fingerprints.len(), first_claims.len());
    fixture
        .state
        .apply(&fill_tx(&first), &fixture.authorizer, 200)
        .unwrap();
    let mut legacy_state = serde_json::to_value(&fixture.state).unwrap();
    let legacy_claims = legacy_state["noteClaims"].as_object_mut().unwrap();
    legacy_claims
        .values_mut()
        .next()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("authorization");
    assert!(serde_json::from_value::<State>(legacy_state).is_err());

    let (mut second, _) = fixture.fill(remaining, 20, 19, [false; 2]);
    let second_claims = second.verify(&fixture.scope, 201).unwrap().claims;
    assert!(second_claims
        .iter()
        .all(|claim| { !first_fingerprints.contains(&claim.authorization.key_fingerprint) }));
    second.openings[0].claim_authorization = first.openings[0].claim_authorization;
    fixture.sign_fill(&mut second);
    let before = fixture.state.clone();
    assert!(fixture
        .state
        .apply(&fill_tx(&second), &fixture.authorizer, 201)
        .is_err());
    assert_eq!(fixture.state, before);
}

#[test]
fn native_claim_redemption_rejects_rebinding_and_legacy_approval_bypass() {
    use defmi::claim_redemption::redeem_claim;
    let mut fixture = Fixture::new();
    let (fill, _) = fixture.fill(fixture.initial, 40, 8, [false, true]);
    let claim = fill
        .verify(&fixture.scope, 200)
        .unwrap()
        .claims
        .into_iter()
        .find(|c| c.kind == NoteClaimKind::Refund && c.asset_id == ASSETS[1])
        .unwrap();
    fixture
        .state
        .apply(&fill_tx(&fill), &fixture.authorizer, 200)
        .unwrap();
    let redemption = {
        let authorizations = fixture.claim_authorizations.borrow();
        let authorization = &authorizations[&claim.authorization.key_fingerprint];
        let redemption = redeem_claim(
            &claim,
            &fixture.key,
            32,
            &Scalar::from(VIEW_SECRETS[1]),
            fixture.wallets[1].opening_key(),
            &fixture.wallets[1].address,
            &[1, 4, 7],
            fixture.authorizer.domain(),
            fixture.state.root(),
            [72; 32],
            authorization,
            201,
            &mut OsRng,
        )
        .unwrap();
        assert!(redeem_claim(
            &claim,
            &fixture.key,
            32,
            &Scalar::from(VIEW_SECRETS[0]),
            fixture.wallets[0].opening_key(),
            &fixture.wallets[0].address,
            &[1, 4, 7],
            fixture.authorizer.domain(),
            fixture.state.root(),
            [73; 32],
            authorization,
            201,
            &mut OsRng
        )
        .is_err());
        redemption
    };
    for mutation in 0..19 {
        let mut bad = redemption.clone();
        match mutation {
            0 => bad.domain.push('x'),
            1 => bad.before_root[0] ^= 1,
            2 => bad.operation_id[0] ^= 1,
            3 => bad.claim_id[0] ^= 1,
            4 => bad.output.asset_id = ASSETS[0],
            5 => bad.output.one_time = fixture.wallets[0].address.spend.compress().to_bytes(),
            6 => {
                bad.output.encrypted_opening = qomm_transport::standing_pool::NoteOpening::Covenant
            }
            7 => bad.output.lock_id = HOLDS[0],
            8 => bad.recipient_signature[40] ^= 1,
            9 => bad.recipient_signature.push(0),
            10 => bad.authorization_signature[0] ^= 1,
            11 => bad.authorization_signature[100] ^= 1,
            12 => bad.authorization_signature = bad.recipient_signature.clone(),
            13 => bad.authorization_key.public_key[0] ^= 1,
            14 => {
                bad.authorization_key.participant_id =
                    zkfmi_crypto::key::ParticipantId::new("another-claim").unwrap();
            }
            15 => bad.authorization_key.key_version += 1,
            16 => bad.version = 1,
            17 => {
                bad.authorization_key.suite =
                    zkfmi_crypto::suite::Suite::new(zkfmi_crypto::suite::SuiteId::MlDsa65)
            }
            _ => bad.authorization_key.purpose = zkfmi_crypto::key::KeyPurpose::Order,
        }
        if (4..=7).contains(&mutation) {
            bad.output.note_id = bad.output.derived_id().unwrap();
        }
        let tx = TransactionEnvelope::new(
            "defmivm.issueNoteClaimRedemption",
            json!({"redemption": bad}),
        )
        .unwrap()
        .encode()
        .unwrap();
        let before = fixture.state.root();
        assert!(
            fixture.state.apply(&tx, &fixture.authorizer, 201).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(fixture.state.root(), before);
    }
    for lifecycle in 0..3 {
        let mut bad = redemption.clone();
        match lifecycle {
            0 => bad.authorization_key.not_before = 202,
            1 => bad.authorization_key.not_after = 201,
            _ => bad.authorization_key.revoked_at = Some(201),
        }
        let tx = TransactionEnvelope::new(
            "defmivm.issueNoteClaimRedemption",
            json!({"redemption": bad}),
        )
        .unwrap()
        .encode()
        .unwrap();
        let before = fixture.state.root();
        assert!(fixture.state.apply(&tx, &fixture.authorizer, 201).is_err());
        assert_eq!(fixture.state.root(), before);
    }
    let expired_tx = TransactionEnvelope::new(
        "defmivm.issueNoteClaimRedemption",
        json!({"redemption": redemption}),
    )
    .unwrap()
    .encode()
    .unwrap();
    let before = fixture.state.root();
    assert!(fixture
        .state
        .apply(&expired_tx, &fixture.authorizer, 1_000)
        .is_err());
    assert_eq!(fixture.state.root(), before);

    let wrong_authorization =
        NoteClaimAuthorization::generate(claim.recipient_commitment, 100, 1_000).unwrap();
    let mut wrong_key = redemption.clone();
    wrong_key.authorization_key = wrong_authorization.key_record().clone();
    let wrong_key_tx = TransactionEnvelope::new(
        "defmivm.issueNoteClaimRedemption",
        json!({"redemption": wrong_key}),
    )
    .unwrap()
    .encode()
    .unwrap();
    assert!(fixture
        .state
        .apply(&wrong_key_tx, &fixture.authorizer, 201)
        .is_err());
    assert_eq!(fixture.state.root(), before);

    let mut legacy = serde_json::to_value(&redemption).unwrap();
    let legacy = legacy.as_object_mut().unwrap();
    legacy.remove("version");
    legacy.remove("authorizationKey");
    legacy.remove("authorizationSignature");
    let legacy_tx = TransactionEnvelope::new(
        "defmivm.issueNoteClaimRedemption",
        json!({"redemption": legacy}),
    )
    .unwrap()
    .encode()
    .unwrap();
    let before = fixture.state.root();
    assert!(fixture
        .state
        .apply(&legacy_tx, &fixture.authorizer, 201)
        .is_err());
    assert_eq!(fixture.state.root(), before);
    // Even a valid governance quorum must not replace ownership of native
    // claims with the old digest-only approval boundary.
    let (_, signers) = committee();
    let legacy = NoteClaimMaterialization {
        operation_id: [74; 32],
        claim_id: claim.claim_id,
        output: redemption.output,
        ownership_proof_digest: [75; 32],
    };
    let before = fixture.state.root();
    assert!(apply(
        &mut fixture.state,
        &fixture.authorizer,
        &signers,
        "defmivm.issueNoteClaimMaterialization",
        "materialization",
        note_materialization_json(&legacy),
        legacy.statement().unwrap(),
        201
    )
    .is_err());
    assert_eq!(fixture.state.root(), before);
}

#[test]
fn native_hybrid_fill_and_cancel_reject_missing_corrupt_or_substituted_approval() {
    let mut fixture = Fixture::new();
    let (fill, _) = fixture.fill(fixture.initial, 40, 14, [false; 2]);
    let release = fixture.release(0, ApplicationReleaseReason::Cancelled, 15);
    let before = serde_json::to_vec(&fixture.state).unwrap();
    for mutation in 0..9 {
        let mut changed = fill.clone();
        match mutation {
            0 => changed.pq_authorization = None,
            1 => changed.pq_authorization.as_mut().unwrap().signatures[0].signature[0] ^= 1,
            2 => changed.signature[0] ^= 1,
            3 => {
                changed
                    .pq_authorization
                    .as_mut()
                    .unwrap()
                    .signatures
                    .pop()
                    .unwrap();
            }
            4 => {
                let approval = changed.pq_authorization.as_mut().unwrap();
                approval.signatures[1] = approval.signatures[0].clone();
            }
            5 => changed.pq_committee.epoch += 1,
            6 => changed.scope.pq_committee_digest[0] ^= 1,
            7 | 8 => {
                let mut payment = zkpi::wire::decode(&changed.instruction).unwrap();
                if mutation == 7 {
                    payment.pq_approval = None;
                } else {
                    payment.pq_approval.as_mut().unwrap().signatures[0].signature[0] ^= 1;
                }
                changed.instruction = zkpi::wire::encode(&payment);
                fixture.sign_fill(&mut changed);
            }
            _ => unreachable!(),
        }
        assert!(
            fixture
                .state
                .apply(&fill_tx(&changed), &fixture.authorizer, 200)
                .is_err(),
            "accepted hybrid fill mutation {mutation}"
        );
        assert_eq!(serde_json::to_vec(&fixture.state).unwrap(), before);
    }
    for mutation in 0..6 {
        let mut changed = release.clone();
        match mutation {
            0 => changed.pq_authorization = None,
            1 => changed.pq_committee = None,
            2 => changed.pq_authorization.as_mut().unwrap().signatures[0].signature[0] ^= 1,
            3 => changed.signature[0] ^= 1,
            4 => changed.pq_committee.as_mut().unwrap().epoch += 1,
            5 => changed.scope.pq_committee_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            fixture
                .state
                .apply(&release_tx(&changed), &fixture.authorizer, 200)
                .is_err(),
            "accepted hybrid cancellation mutation {mutation}"
        );
        assert_eq!(serde_json::to_vec(&fixture.state).unwrap(), before);
    }
    fixture
        .state
        .apply(&fill_tx(&fill), &fixture.authorizer, 200)
        .unwrap();
}

#[test]
fn expired_pq_keys_block_new_execution_but_preserve_accepted_fill_integrity() {
    let mut fixture = Fixture::with_pq_expiry(250);
    let (fill, _) = fixture.fill(fixture.initial, 40, 16, [false; 2]);
    assert!(zkpi::wire::decode(&fill.instruction).unwrap().deadline > 250);
    let before = fixture.state.root();
    assert!(fixture
        .state
        .apply(&fill_tx(&fill), &fixture.authorizer, 251)
        .is_err());
    assert_eq!(fixture.state.root(), before);
    fixture
        .state
        .apply(&fill_tx(&fill), &fixture.authorizer, 200)
        .unwrap();
    assert!(fill.verify(&fixture.scope, 251).is_err());
    fill.verify_archived(&fixture.scope).unwrap();
    let mut corrupt = fill;
    corrupt.pq_authorization.as_mut().unwrap().signatures[0].signature[0] ^= 1;
    assert!(corrupt.verify_archived(&fixture.scope).is_err());
}
