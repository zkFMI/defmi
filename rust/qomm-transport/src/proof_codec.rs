//! Canonical bounded encoding for the final public threshold proofs handed
//! from the MPC/proof cluster to DeFMI admission.
//!
//! Node round messages already have their own codecs.  This format covers only
//! verifier-complete proofs and therefore contains no Shamir share, nonce, or
//! witness opening.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::quote_proof::{
    quote_proof_digest, BitValidityProof, EligibilityProof, Gate, MakerCommitments, MakerProof,
    MinimalityProof, Public as QuotePublic, QuoteCircuit, QuoteProof, RegisteredPolicy,
};
use qomm_proofs::threshold_range::ThresholdRangeProof;
use qomm_zk::sigma::{OpeningProof, ProductProof};

use crate::dvp_issuer::DvpProofs;

const RANGE_MAGIC: &[u8; 8] = b"QOMMRPF1";
const DVP_MAGIC: &[u8; 8] = b"QOMMDPF1";
const QUOTE_MAGIC: &[u8; 8] = b"QOMMQPF1";
const MAX_BITS: usize = 64;
const MAX_QUOTE_MAKERS: usize = 24;
const MAX_QUOTE_BYTES: usize = 768 * 1024;
const POINT_BYTES: usize = 32;
const PRODUCT_BYTES: usize = 5 * 32;
const OPENING_BYTES: usize = 3 * 32;

fn put_point(out: &mut Vec<u8>, point: &RistrettoPoint) {
    out.extend_from_slice(point.compress().as_bytes());
}

fn put_scalar(out: &mut Vec<u8>, scalar: &Scalar) {
    out.extend_from_slice(&scalar.to_bytes());
}

fn put_product(out: &mut Vec<u8>, proof: &ProductProof) {
    put_point(out, &proof.t_factor);
    put_point(out, &proof.t_product);
    put_scalar(out, &proof.z_b);
    put_scalar(out, &proof.z_rb);
    put_scalar(out, &proof.z_s);
}

fn put_opening(out: &mut Vec<u8>, proof: &OpeningProof) {
    put_point(out, &proof.t);
    put_scalar(out, &proof.z_value);
    put_scalar(out, &proof.z_blinding);
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize, what: &str) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(count)
            .ok_or_else(|| format!("{what} offset overflow"))?;
        let value = self
            .raw
            .get(self.at..end)
            .ok_or_else(|| format!("truncated {what}"))?;
        self.at = end;
        Ok(value)
    }

    fn u16(&mut self, what: &str) -> Result<usize, String> {
        Ok(u16::from_be_bytes(self.take(2, what)?.try_into().expect("two bytes")) as usize)
    }

    fn u8(&mut self, what: &str) -> Result<u8, String> {
        Ok(self.take(1, what)?[0])
    }

    fn u32(&mut self, what: &str) -> Result<usize, String> {
        usize::try_from(u32::from_be_bytes(
            self.take(4, what)?.try_into().expect("four bytes"),
        ))
        .map_err(|_| format!("{what} is outside this platform"))
    }

    fn u64(&mut self, what: &str) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8, what)?.try_into().expect("eight bytes"),
        ))
    }

    fn i64(&mut self, what: &str) -> Result<i64, String> {
        Ok(i64::from_be_bytes(
            self.take(8, what)?.try_into().expect("eight bytes"),
        ))
    }

    fn bytes32(&mut self, what: &str) -> Result<[u8; 32], String> {
        Ok(self.take(32, what)?.try_into().expect("32 bytes"))
    }

    fn point(&mut self) -> Result<RistrettoPoint, String> {
        let raw: [u8; POINT_BYTES] = self
            .take(POINT_BYTES, "Ristretto point")?
            .try_into()
            .expect("32 bytes");
        CompressedRistretto(raw)
            .decompress()
            .ok_or_else(|| "proof contains a non-canonical Ristretto point".into())
    }

    fn scalar(&mut self) -> Result<Scalar, String> {
        let raw: [u8; 32] = self
            .take(32, "Ristretto scalar")?
            .try_into()
            .expect("32 bytes");
        Option::<Scalar>::from(Scalar::from_canonical_bytes(raw))
            .ok_or_else(|| "proof contains a non-canonical Ristretto scalar".into())
    }

    fn product(&mut self) -> Result<ProductProof, String> {
        Ok(ProductProof {
            t_factor: self.point()?,
            t_product: self.point()?,
            z_b: self.scalar()?,
            z_rb: self.scalar()?,
            z_s: self.scalar()?,
        })
    }

    fn opening(&mut self) -> Result<OpeningProof, String> {
        Ok(OpeningProof {
            t: self.point()?,
            z_value: self.scalar()?,
            z_blinding: self.scalar()?,
        })
    }

    fn finish(self) -> Result<(), String> {
        if self.at == self.raw.len() {
            Ok(())
        } else {
            Err(format!(
                "proof encoding has {} trailing bytes",
                self.raw.len() - self.at
            ))
        }
    }
}

pub fn encode_threshold_range(proof: &ThresholdRangeProof) -> Result<Vec<u8>, String> {
    if proof.bits == 0
        || proof.bits > MAX_BITS
        || proof.bit_commitments.len() != proof.bits
        || proof.bit_proofs.len() != proof.bits
    {
        return Err("threshold range proof shape is outside the wire bound".into());
    }
    let bits = u16::try_from(proof.bits).map_err(|_| "threshold proof width overflow")?;
    let mut out = Vec::with_capacity(
        RANGE_MAGIC.len() + 2 + proof.bits * (POINT_BYTES + PRODUCT_BYTES) + OPENING_BYTES,
    );
    out.extend_from_slice(RANGE_MAGIC);
    out.extend_from_slice(&bits.to_be_bytes());
    for commitment in &proof.bit_commitments {
        put_point(&mut out, commitment);
    }
    for bit in &proof.bit_proofs {
        put_product(&mut out, bit);
    }
    put_opening(&mut out, &proof.linkage);
    Ok(out)
}

pub fn decode_threshold_range(raw: &[u8]) -> Result<ThresholdRangeProof, String> {
    let mut reader = Reader { raw, at: 0 };
    if reader.take(RANGE_MAGIC.len(), "range-proof magic")? != RANGE_MAGIC {
        return Err("wrong threshold range proof magic".into());
    }
    let bits = reader.u16("range-proof width")?;
    if bits == 0 || bits > MAX_BITS {
        return Err("threshold range proof width is outside the wire bound".into());
    }
    let bit_commitments = (0..bits)
        .map(|_| reader.point())
        .collect::<Result<Vec<_>, _>>()?;
    let bit_proofs = (0..bits)
        .map(|_| reader.product())
        .collect::<Result<Vec<_>, _>>()?;
    let linkage = reader.opening()?;
    reader.finish()?;
    Ok(ThresholdRangeProof {
        bit_commitments,
        bit_proofs,
        linkage,
        bits,
    })
}

pub fn encode_dvp_proofs(proofs: &DvpProofs) -> Result<Vec<u8>, String> {
    let securities = encode_threshold_range(&proofs.securities_remainder)?;
    let cash = encode_threshold_range(&proofs.cash_remainder)?;
    let mut out =
        Vec::with_capacity(DVP_MAGIC.len() + PRODUCT_BYTES + 8 + securities.len() + cash.len());
    out.extend_from_slice(DVP_MAGIC);
    put_product(&mut out, &proofs.product);
    out.extend_from_slice(
        &u32::try_from(securities.len())
            .map_err(|_| "securities proof is too large")?
            .to_be_bytes(),
    );
    out.extend_from_slice(&securities);
    out.extend_from_slice(
        &u32::try_from(cash.len())
            .map_err(|_| "cash proof is too large")?
            .to_be_bytes(),
    );
    out.extend_from_slice(&cash);
    Ok(out)
}

pub fn decode_dvp_proofs(raw: &[u8]) -> Result<DvpProofs, String> {
    let mut reader = Reader { raw, at: 0 };
    if reader.take(DVP_MAGIC.len(), "DvP-proof magic")? != DVP_MAGIC {
        return Err("wrong threshold DvP proof magic".into());
    }
    let product = reader.product()?;
    let securities_len = reader.u32("securities proof length")?;
    let securities = decode_threshold_range(reader.take(securities_len, "securities proof")?)?;
    let cash_len = reader.u32("cash proof length")?;
    let cash = decode_threshold_range(reader.take(cash_len, "cash proof")?)?;
    reader.finish()?;
    Ok(DvpProofs {
        product,
        securities_remainder: securities,
        cash_remainder: cash,
    })
}

/// Verifier-complete quote evidence produced by the threshold proof cluster.
///
/// The fixed 32-byte context is the request-bound transcript context used by
/// every proof party. Only threshold range proofs and square bit proofs are
/// accepted here: accepting the local single-prover variants would silently
/// weaken the production claim that no one node held the pricing witnesses.
#[derive(Debug)]
pub struct QuoteVerificationBundle {
    pub context: [u8; 32],
    pub eligibility_bits: usize,
    pub span_bits: usize,
    pub public: QuotePublic,
    pub proof: QuoteProof,
}

impl QuoteVerificationBundle {
    pub fn verify(&self) -> Result<[u8; 32], String> {
        if self.public.registry.is_empty() || self.public.registry.len() > MAX_QUOTE_MAKERS {
            return Err("quote registry size is outside the settlement bound".into());
        }
        let circuit =
            QuoteCircuit::try_new(self.eligibility_bits, self.span_bits).map_err(str::to_string)?;
        circuit
            .verify(&self.proof, &self.public, &self.context)
            .map_err(|error| format!("quote proof verification failed: {error:?}"))?;
        Ok(quote_proof_digest(&self.public, &self.proof))
    }
}

fn put_count(out: &mut Vec<u8>, value: usize, what: &str) -> Result<(), String> {
    out.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| format!("{what} count exceeds the wire bound"))?
            .to_be_bytes(),
    );
    Ok(())
}

fn put_sized(out: &mut Vec<u8>, value: &[u8], what: &str) -> Result<(), String> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| format!("{what} exceeds the wire bound"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}

fn put_square_bit(out: &mut Vec<u8>, proof: &BitValidityProof) -> Result<(), String> {
    match proof {
        BitValidityProof::Square(proof) => {
            put_product(out, proof);
            Ok(())
        }
        BitValidityProof::Disjunction(_) => {
            Err("single-prover bit proof is forbidden in settlement evidence".into())
        }
    }
}

fn put_gate(out: &mut Vec<u8>, gate: &Gate) -> Result<(), String> {
    put_point(out, &gate.commitment);
    put_square_bit(out, &gate.bit_proof)?;
    put_product(out, &gate.product);
    put_point(out, &gate.product_commitment);
    put_point(out, &gate.witness_commitment);
    Ok(())
}

fn decode_square_bit(reader: &mut Reader<'_>) -> Result<BitValidityProof, String> {
    Ok(BitValidityProof::Square(reader.product()?))
}

fn decode_gate(reader: &mut Reader<'_>) -> Result<Gate, String> {
    Ok(Gate {
        commitment: reader.point()?,
        bit_proof: decode_square_bit(reader)?,
        product: reader.product()?,
        product_commitment: reader.point()?,
        witness_commitment: reader.point()?,
    })
}

fn policy_points(policy: &RegisteredPolicy) -> [RistrettoPoint; 9] {
    [
        policy.ask_level,
        policy.spread,
        policy.slope,
        policy.invcoef,
        policy.inv,
        policy.maxqty,
        policy.expiry,
        policy.active,
        policy.use_ref,
    ]
}

fn commitment_points(commitments: &MakerCommitments) -> [RistrettoPoint; 14] {
    [
        commitments.slope,
        commitments.invcoef,
        commitments.inv,
        commitments.depth,
        commitments.skew,
        commitments.fits,
        commitments.fresh,
        commitments.active,
        commitments.ok,
        commitments.fresh_strict,
        commitments.both,
        commitments.cost,
        commitments.gated,
        commitments.shifted_cost,
    ]
}

fn decode_commitments(reader: &mut Reader<'_>) -> Result<MakerCommitments, String> {
    Ok(MakerCommitments {
        slope: reader.point()?,
        invcoef: reader.point()?,
        inv: reader.point()?,
        depth: reader.point()?,
        skew: reader.point()?,
        fits: reader.point()?,
        fresh: reader.point()?,
        active: reader.point()?,
        ok: reader.point()?,
        fresh_strict: reader.point()?,
        both: reader.point()?,
        cost: reader.point()?,
        gated: reader.point()?,
        shifted_cost: reader.point()?,
    })
}

fn put_threshold(out: &mut Vec<u8>, proof: &ThresholdRangeProof) -> Result<(), String> {
    put_sized(
        out,
        &encode_threshold_range(proof)?,
        "threshold range proof",
    )
}

fn decode_threshold(reader: &mut Reader<'_>) -> Result<ThresholdRangeProof, String> {
    let length = reader.u32("threshold range proof length")?;
    decode_threshold_range(reader.take(length, "threshold range proof")?)
}

/// Encode the exact public quote statement and all proof elements needed by an
/// Avalanche validator. The result contains no price-policy opening, inventory,
/// amount, price, or Shamir share.
pub fn encode_quote_verification(value: &QuoteVerificationBundle) -> Result<Vec<u8>, String> {
    value.verify()?;
    let makers = value.public.registry.len();
    if value.proof.maker_proofs.len() != makers
        || value.proof.key_commitments.len() != makers
        || makers > MAX_QUOTE_MAKERS
    {
        return Err("quote proof vectors do not match the bounded registry".into());
    }
    let minimality = match &value.proof.minimality {
        MinimalityProof::Threshold(proofs) if proofs.len() == makers => proofs,
        MinimalityProof::Threshold(_) => {
            return Err("quote proof has the wrong minimality population".into())
        }
        MinimalityProof::Bulletproof { .. } => {
            return Err("single-prover minimality proof is forbidden in settlement evidence".into())
        }
    };
    let mut out = Vec::with_capacity(32 * 1024);
    out.extend_from_slice(QUOTE_MAGIC);
    out.extend_from_slice(
        &u16::try_from(value.eligibility_bits)
            .map_err(|_| "quote eligibility width exceeds the wire bound")?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(value.span_bits)
            .map_err(|_| "quote span width exceeds the wire bound")?
            .to_be_bytes(),
    );
    out.extend_from_slice(&value.context);
    put_point(&mut out, &value.public.qty_commitment);
    out.extend_from_slice(&value.public.now.to_be_bytes());
    out.extend_from_slice(&value.public.sentinel.to_be_bytes());
    out.extend_from_slice(&value.public.n_slots.to_be_bytes());
    out.push(value.public.direction);
    out.extend_from_slice(&value.public.asset.to_be_bytes());
    out.extend_from_slice(&value.public.reference_price.to_be_bytes());
    out.extend_from_slice(&value.public.registry_digest);
    out.extend_from_slice(&value.public.market_digest);
    out.extend_from_slice(&value.public.slot.to_be_bytes());
    put_count(&mut out, makers, "quote maker")?;
    for policy in &value.public.registry {
        out.extend_from_slice(&policy.maker_asset.to_be_bytes());
        for point in policy_points(policy) {
            put_point(&mut out, &point);
        }
    }
    out.extend_from_slice(
        &u16::try_from(value.proof.winner_index)
            .map_err(|_| "quote winner index exceeds the wire bound")?
            .to_be_bytes(),
    );
    out.extend_from_slice(&value.proof.winner_value.to_be_bytes());
    put_count(
        &mut out,
        value.proof.maker_proofs.len(),
        "quote maker proof",
    )?;
    for maker in &value.proof.maker_proofs {
        put_product(&mut out, &maker.depth);
        put_product(&mut out, &maker.skew);
        put_product(&mut out, &maker.gate_cost);
        match &maker.eligibility {
            EligibilityProof::Threshold { fits, fresh } => {
                put_threshold(&mut out, fits)?;
                put_threshold(&mut out, fresh)?;
            }
            EligibilityProof::Bulletproof { .. } => {
                return Err(
                    "single-prover eligibility proof is forbidden in settlement evidence".into(),
                )
            }
        }
        put_square_bit(&mut out, &maker.active_bit)?;
        put_square_bit(&mut out, &maker.reference_bit)?;
        put_gate(&mut out, &maker.fits_gate)?;
        put_gate(&mut out, &maker.fresh_gate)?;
        put_product(&mut out, &maker.conjunction.0);
        put_product(&mut out, &maker.conjunction.1);
        for point in commitment_points(&maker.commitments) {
            put_point(&mut out, &point);
        }
    }
    put_opening(&mut out, &value.proof.winner_opening);
    put_count(&mut out, minimality.len(), "quote minimality proof")?;
    for proof in minimality {
        put_threshold(&mut out, proof)?;
    }
    put_count(
        &mut out,
        value.proof.key_commitments.len(),
        "quote key commitment",
    )?;
    for point in &value.proof.key_commitments {
        put_point(&mut out, point);
    }
    if out.len() > MAX_QUOTE_BYTES {
        return Err("encoded quote proof exceeds the settlement transaction bound".into());
    }
    Ok(out)
}

/// Decode and immediately verify threshold quote evidence. Returning an object
/// is therefore also evidence that its canonical digest was recomputed from
/// the complete statement, rather than trusted from the submitter.
pub fn decode_quote_verification(raw: &[u8]) -> Result<QuoteVerificationBundle, String> {
    if raw.is_empty() || raw.len() > MAX_QUOTE_BYTES {
        return Err("encoded quote proof is outside the settlement transaction bound".into());
    }
    let mut reader = Reader { raw, at: 0 };
    if reader.take(QUOTE_MAGIC.len(), "quote-proof magic")? != QUOTE_MAGIC {
        return Err("wrong threshold quote proof magic".into());
    }
    let eligibility_bits = reader.u16("quote eligibility width")?;
    let span_bits = reader.u16("quote span width")?;
    let context = reader.bytes32("quote transcript context")?;
    let qty_commitment = reader.point()?;
    let now = reader.i64("quote time")?;
    let sentinel = reader.i64("quote sentinel")?;
    let n_slots = reader.i64("quote slot population")?;
    let direction = reader.u8("quote direction")?;
    let asset = u32::from_be_bytes(
        reader
            .take(4, "quote asset")?
            .try_into()
            .expect("four bytes"),
    );
    let reference_price = reader.i64("quote reference price")?;
    let registry_digest = reader.bytes32("quote registry digest")?;
    let market_digest = reader.bytes32("quote market digest")?;
    let slot = reader.u64("quote slot")?;
    let makers = reader.u16("quote maker count")?;
    if makers == 0 || makers > MAX_QUOTE_MAKERS {
        return Err("quote registry size is outside the settlement bound".into());
    }
    let mut registry = Vec::with_capacity(makers);
    for _ in 0..makers {
        let maker_asset = u32::from_be_bytes(
            reader
                .take(4, "maker asset")?
                .try_into()
                .expect("four bytes"),
        );
        registry.push(RegisteredPolicy {
            maker_asset,
            ask_level: reader.point()?,
            spread: reader.point()?,
            slope: reader.point()?,
            invcoef: reader.point()?,
            inv: reader.point()?,
            maxqty: reader.point()?,
            expiry: reader.point()?,
            active: reader.point()?,
            use_ref: reader.point()?,
        });
    }
    let public = QuotePublic {
        qty_commitment,
        now,
        sentinel,
        n_slots,
        direction,
        asset,
        reference_price,
        registry,
        registry_digest,
        market_digest,
        slot,
    };
    let winner_index = reader.u16("quote winner index")?;
    let winner_value = reader.u64("quote winner value")?;
    let proof_makers = reader.u16("quote maker-proof count")?;
    if proof_makers != makers {
        return Err("quote maker-proof population differs from its registry".into());
    }
    let mut maker_proofs = Vec::with_capacity(makers);
    for _ in 0..makers {
        maker_proofs.push(MakerProof {
            depth: reader.product()?,
            skew: reader.product()?,
            gate_cost: reader.product()?,
            eligibility: EligibilityProof::Threshold {
                fits: Box::new(decode_threshold(&mut reader)?),
                fresh: Box::new(decode_threshold(&mut reader)?),
            },
            active_bit: decode_square_bit(&mut reader)?,
            reference_bit: decode_square_bit(&mut reader)?,
            fits_gate: decode_gate(&mut reader)?,
            fresh_gate: decode_gate(&mut reader)?,
            conjunction: (reader.product()?, reader.product()?),
            commitments: decode_commitments(&mut reader)?,
        });
    }
    let winner_opening = reader.opening()?;
    let minimality_count = reader.u16("quote minimality-proof count")?;
    if minimality_count != makers {
        return Err("quote minimality population differs from its registry".into());
    }
    let minimality = MinimalityProof::Threshold(
        (0..minimality_count)
            .map(|_| decode_threshold(&mut reader))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let key_count = reader.u16("quote key-commitment count")?;
    if key_count != makers {
        return Err("quote key population differs from its registry".into());
    }
    let key_commitments = (0..key_count)
        .map(|_| reader.point())
        .collect::<Result<Vec<_>, _>>()?;
    reader.finish()?;
    let bundle = QuoteVerificationBundle {
        context,
        eligibility_bits,
        span_bits,
        public,
        proof: QuoteProof {
            winner_index,
            winner_value,
            maker_proofs,
            winner_opening,
            minimality,
            key_commitments,
        },
    };
    bundle.verify()?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    fn product(value: u64) -> ProductProof {
        ProductProof {
            t_factor: RistrettoPoint::identity(),
            t_product: RistrettoPoint::identity(),
            z_b: Scalar::from(value),
            z_rb: Scalar::from(value + 1),
            z_s: Scalar::from(value + 2),
        }
    }

    fn range() -> ThresholdRangeProof {
        ThresholdRangeProof {
            bit_commitments: vec![RistrettoPoint::identity(); 2],
            bit_proofs: vec![product(1), product(4)],
            linkage: OpeningProof {
                t: RistrettoPoint::identity(),
                z_value: Scalar::from(7_u64),
                z_blinding: Scalar::from(8_u64),
            },
            bits: 2,
        }
    }

    #[test]
    fn final_public_proofs_round_trip_and_reject_trailing_bytes() {
        let proofs = DvpProofs {
            product: product(9),
            securities_remainder: range(),
            cash_remainder: range(),
        };
        let raw = encode_dvp_proofs(&proofs).unwrap();
        let decoded = decode_dvp_proofs(&raw).unwrap();
        assert_eq!(decoded.product.z_b, proofs.product.z_b);
        assert_eq!(decoded.cash_remainder.bits, 2);
        let mut trailing = raw;
        trailing.push(0);
        assert!(decode_dvp_proofs(&trailing).is_err());
    }
}
