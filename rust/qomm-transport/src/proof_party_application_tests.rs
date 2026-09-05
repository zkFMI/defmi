//! Unit tests of the local authorization boundary, not evidence of an MPC run.
use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn config(root: &Path) -> ProofPartyConfig {
    ProofPartyConfig {
        node: 0,
        allowed_root: root.into(),
        state_file: root.join("party.qps"),
        state_passphrase: vec![1; 32],
        n_mm: 1,
        n_parties: 7,
        threshold: 2,
        amount_bits: 32,
        price_bits: 32,
        remainder_bits: 32,
        complete_quote_proof: false,
        quote_eligibility_bits: 34,
        quote_span_bits: 32,
        trusted_defmi_receipt_public: None,
        allow_health_signing: false,
    }
}

fn fixture(root: &Path) -> ProofParty {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut party = ProofParty::new(config(root)).unwrap();
    let (mut shares, public) = qomm_zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
    let share = shares
        .remove(&frost::Identifier::try_from(1_u16).unwrap())
        .unwrap();
    party.frost_key = Some(frost::keys::KeyPackage::try_from(share).unwrap());
    party.frost_public = Some(public);
    party.frost_session = Some([9; 32]);
    party.completed.insert([1; 32]);
    let point = (party.key.g * Scalar::from(2_u64)).compress().to_bytes();
    party.completed_evidence.insert(
        [1; 32],
        CompletedProof {
            payment_digest: [2; 64],
            quote_digest: [3; 32],
            winning_policy_digest: None,
            typed_message_digest: None,
            maker_handle: Some(point),
            taker_handle: Some(point),
            maker_is_payer: Some(false),
            securities_reserve: Some(point),
            cash_reserve: Some(point),
            opening_shares: [
                "securities_delivery",
                "securities_refund",
                "cash_delivery",
                "cash_refund",
            ]
            .map(|leg| (leg.into(), json!({"unit_fixture": leg})))
            .into_iter()
            .collect(),
            application_action_digest: None,
        },
    );
    party
}

struct TestVerifier {
    message: [u8; 32],
    action: [u8; 32],
    reject: bool,
}

impl ApplicationStatementVerifier for TestVerifier {
    fn verify(
        &self,
        proof: CompletedApplicationProof<'_>,
    ) -> Result<ApplicationStatementAuthorization, String> {
        assert_eq!(proof.job_id, [1; 32]);
        assert_eq!(proof.payment_digest, [2; 64]);
        assert_eq!(proof.quote_digest, [3; 32]);
        assert_eq!(proof.opening_shares.len(), 4);
        if self.reject {
            return Err("test verifier rejected the statement".into());
        }
        Ok(ApplicationStatementAuthorization {
            message: self.message,
            action_digest: self.action,
        })
    }
}

#[test]
fn no_rpc_or_incomplete_evidence_can_enable_application_signing() {
    let root = TempDir::new().unwrap();
    let mut party = fixture(root.path());
    let verifier = TestVerifier {
        message: [4; 32],
        action: [5; 32],
        reject: false,
    };
    for method in [
        "authorize_application_statement",
        "authorize_oclob_native_fill",
        "authorize_frost",
    ] {
        let response = party.handle(ProofRequest {
            id: 1,
            method: method.into(),
            params: json!({}),
        });
        assert!(!response.ok, "generic proof transport exposed {method}");
    }
    assert!(party
        .authorize_application_statement([7; 32], &verifier)
        .is_err());
    let proof = party.completed_evidence.get_mut(&[1; 32]).unwrap();
    proof.opening_shares.clear(); // Old durable records remain readable, but cannot sign native fills.
    assert!(party
        .authorize_application_statement([1; 32], &verifier)
        .is_err());
    assert!(party.frost_authorized.is_empty());
    party
        .completed_evidence
        .get_mut(&[1; 32])
        .unwrap()
        .opening_shares = [
        "securities_delivery",
        "securities_refund",
        "cash_delivery",
        "cash_refund",
    ]
    .map(|leg| (leg.into(), json!({"unit_fixture": leg})))
    .into_iter()
    .collect();
    let rejecting = TestVerifier {
        reject: true,
        ..verifier
    };
    assert!(party
        .authorize_application_statement([1; 32], &rejecting)
        .is_err());
    assert!(party.frost_authorized.is_empty());
    assert!(party.completed_evidence[&[1; 32]]
        .application_action_digest
        .is_none());
    party.state_healthy = false;
    assert!(party
        .authorize_application_statement([1; 32], &verifier)
        .is_err());
}

#[test]
fn application_action_and_one_use_nonce_survive_restart() {
    let root = TempDir::new().unwrap();
    let mut party = fixture(root.path());
    let first = TestVerifier {
        message: [4; 32],
        action: [5; 32],
        reject: false,
    };
    assert_eq!(
        party
            .authorize_application_statement([1; 32], &first)
            .unwrap(),
        [4; 32]
    );
    drop(party);
    let mut party = ProofParty::new(config(root.path())).unwrap();
    assert_eq!(
        party.completed_evidence[&[1; 32]].application_action_digest,
        Some([5; 32])
    );
    let another_action = TestVerifier {
        message: [6; 32],
        action: [7; 32],
        reject: false,
    };
    assert!(party
        .authorize_application_statement([1; 32], &another_action)
        .is_err());
    let new_parent = TestVerifier {
        message: [6; 32],
        action: [5; 32],
        reject: false,
    };
    assert!(party
        .authorize_application_statement([1; 32], &new_parent)
        .is_ok());
    let signing_job = ProofParty::signing_job(&first.message);
    let response = party.handle(ProofRequest {
        id: 2, method: "frost_commit".into(),
        params: json!({"job_id": hex::encode(signing_job), "message": BASE64.encode(first.message)}),
    });
    assert!(response.ok, "{:?}", response.error);
    drop(party);
    let mut party = ProofParty::new(config(root.path())).unwrap();
    assert!(party
        .authorize_application_statement([1; 32], &first)
        .is_err());
    assert!(party
        .authorize_application_statement([1; 32], &another_action)
        .is_err());
}
