//! Real cryptographic proofs through the native VM, not mocked verification.
//! Genesis assets/facilities and committee keys are synthetic unit fixtures;
//! this is not independent-node or live Avalanche acceptance evidence.

use super::*;
use qomm_defmi::application_reservation::{
    ApplicationNoteReservation, ApplicationReserveMandate, ApplicationReserveScope,
};
use qomm_defmi::application_settlement::{
    point, ApplicationNoteFill, ApplicationNoteRelease, ApplicationOpening,
    ApplicationReleaseReason, ApplicationSpendHead,
};
use qomm_defmi::facility::CreditFacilityRelationProof;
use qomm_defmi::notes::{encode_spend_proof, NoteLedger, Wallet};
use qomm_proofs::opening_envelope::{encrypt_opening_share, opening_context};

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
    scope: ApplicationReserveScope,
    wallets: [Wallet; 2],
    initial: Witness,
}

impl Fixture {
    fn new() -> Self {
        let (authorizer, signers) = committee();
        let (shares, public) = qomm_zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
        let scope = ApplicationReserveScope {
            application_binding: [207; 32],
            venue_id: [208; 32],
            defmi_id: [209; 32],
            committee_key_digest: Sha256::digest(public.serialize().unwrap()).into(),
            committee_epoch: 1,
            amount_bits: 32,
        };
        let mut fixture = Self {
            state: State::default(),
            authorizer,
            key: Pedersen::new(b"qomm:defmi:v1"),
            keys: frost_key_packages(shares),
            public,
            scope,
            wallets: VIEW_SECRETS
                .map(|value| Wallet::from_parts(Scalar::from(value), Scalar::from(value + 10))),
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

    fn reserve(&mut self, index: usize, signers: &BTreeMap<String, SigningKey>) {
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
        let source = ledger.build_note(
            &wallet.address,
            value + 10,
            self.key.commit_u64(value + 10, &source_blind),
            &source_blind,
            &mut OsRng,
        );
        let other = ledger.build_note(
            &decoy.address,
            25,
            self.key.commit_u64(25, &source_blind),
            &source_blind,
            &mut OsRng,
        );
        ledger.add(source);
        ledger.add(other);
        for note in &ledger.notes {
            insert_note(
                &mut self.state,
                &NoteOutput::from_note(note, asset, ZERO).unwrap(),
            )
            .unwrap();
        }
        let participant = SigningKey::from_bytes(&[226 + index as u8; 32]);
        let mandate = ApplicationReserveMandate {
            version: 1,
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
            participant_public: participant.verifying_key().to_bytes(),
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
        fill.signature = frost_sign(&self.keys, &self.public, &fill.signing_message().unwrap())
            .serialize()
            .unwrap();
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
        let payment = partial.sealed(signature);
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
            qomm_defmi::asset_link::prove(&self.key, ASSETS[0], &asset, &asset_blind, &mut OsRng)
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
            version: 1,
            scope: self.scope.clone(),
            before_root: self.state.root(),
            operation_id: [tag + 40; 32],
            mpc_result_digest: result,
            securities_asset: ASSETS[0],
            cash_asset: ASSETS[1],
            securities: head(0),
            cash: head(1),
            instruction: qomm_zkpi::wire::encode(&payment),
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
                ),
                opening(
                    nonce,
                    "securities_refund",
                    next.values[0],
                    next.blindings[0] + deltas[0],
                    &self.wallets[0],
                ),
                opening(
                    nonce,
                    "cash_delivery",
                    values[1],
                    blinds[1],
                    &self.wallets[0],
                ),
                opening(
                    nonce,
                    "cash_refund",
                    next.values[1],
                    next.blindings[1] + deltas[1],
                    &self.wallets[1],
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
                &mut OsRng,
            )
            .unwrap()
        })
        .collect();
    ApplicationOpening::from_domain(
        &OpeningEnvelope::new(context, 3, recipient.address.view, shares).unwrap(),
    )
    .unwrap()
}

fn fill_tx(fill: &ApplicationNoteFill) -> Vec<u8> {
    TransactionEnvelope::new("defmivm.issueApplicationNoteFill", json!({"fill": fill}))
        .unwrap()
        .encode()
        .unwrap()
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
                .decrypt(&Scalar::from(VIEW_SECRETS[index]), &quorum)
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
    let (_, other_key) = qomm_zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
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
    fixture.state = restored(&fixture.state);
    let cancel = fixture.release(0, ApplicationReleaseReason::Cancelled, 22);
    let mut unsigned = cancel.clone();
    unsigned.signature.clear();
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
        let encrypted = claim.opening_envelope.domain().unwrap();
        let (value, blind) = encrypted
            .decrypt(&Scalar::from(VIEW_SECRETS[index]), &[1, 4, 7])
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
    receipts: std::sync::Mutex<BTreeMap<String, qomm_defmi::avalanche::AcceptedTransition>>,
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
            qomm_defmi::avalanche::AcceptedTransition {
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

impl qomm_defmi::avalanche::AvalancheClient for NativeClient {
    fn issue_asset(
        &self,
        _: &qomm_defmi::facility::AssetDefinition,
        _: &QuorumApproval,
        _: [u8; 32],
    ) -> Result<String, String> {
        Err("asset admission is outside this application-lifecycle test client".into())
    }

    fn issue_account(
        &self,
        _: &qomm_defmi::facility::AccountOpening,
        _: &QuorumApproval,
        _: [u8; 32],
    ) -> Result<String, String> {
        Err("the application-note test must not open an account".into())
    }

    fn issue_settlement(
        &self,
        _: &qomm_defmi::facility::SettlementOrder,
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
    ) -> Result<qomm_defmi::avalanche::AcceptedTransition, String> {
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
    let bridge = qomm_defmi::avalanche::AvalancheNoteBridge::new(&fixture.authorizer, &client);
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
