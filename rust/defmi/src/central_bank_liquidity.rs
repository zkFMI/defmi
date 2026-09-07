//! Bank-of-Japan-style common collateral and intraday overdraft.
//!
//! This is deliberately not a prefunded guarantee account.  A participating
//! legal entity has one common collateral pool.  Its usable intraday liquidity
//! is derived from the pool after subtracting other secured central-bank
//! exposures, outstanding overdraft and still-live settlement reservations.
//! JGB receipt, pledge, overdraft draw and payment can then be applied as one
//! state transition, matching BOJ-NET's simultaneous collateral facility.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const BPS: u128 = 10_000;
const PRICE_SCALE: u128 = 1_000_000;
const INDEX_SCALE: u128 = 1_000_000;
const PAR: u128 = 100;
const ZERO: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStatus {
    Active,
    CollateralShortfall,
    Overdue,
    Suspended,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Active,
    Consumed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BojParticipant {
    /// Opaque commitment to the legal entity.  Branches do not receive
    /// independent collateral pools.
    pub legal_entity_id: [u8; 32],
    pub funds_account_id: [u8; 32],
    pub jgb_account_id: [u8; 32],
    pub current_account_balance_yen: u64,
    pub other_secured_exposure_yen: u64,
    pub intraday_overdraft_yen: u64,
    pub business_day: u32,
    pub repayment_deadline: u64,
    pub business_day_closed: bool,
    pub sequence: u64,
    pub status: ParticipantStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JgbCollateralLot {
    pub lot_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub owner_legal_entity_id: [u8; 32],
    pub face_value_yen: u64,
    /// Market price per JPY 100, with six decimal places.
    pub market_price_per_100_micros: u64,
    /// Inflation-linked coefficient.  1_000_000 means 1.0.
    pub index_ratio_ppm: u64,
    /// BOJ valuation percentage after its haircut.  9_700 means 97%.
    pub valuation_rate_bps: u16,
    pub valuation_epoch: u64,
    pub pledged: bool,
    pub sequence: u64,
}

impl JgbCollateralLot {
    pub fn collateral_value_yen(&self) -> Result<u64, BojLiquidityError> {
        if self.face_value_yen == 0
            || self.market_price_per_100_micros == 0
            || self.index_ratio_ppm == 0
            || self.valuation_rate_bps == 0
            || u128::from(self.valuation_rate_bps) > BPS
        {
            return Err(BojLiquidityError::InvalidCollateral);
        }
        let numerator = u128::from(self.face_value_yen)
            .checked_mul(u128::from(self.market_price_per_100_micros))
            .and_then(|value| value.checked_mul(u128::from(self.index_ratio_ppm)))
            .and_then(|value| value.checked_mul(u128::from(self.valuation_rate_bps)))
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let denominator = PAR
            .checked_mul(PRICE_SCALE)
            .and_then(|value| value.checked_mul(INDEX_SCALE))
            .and_then(|value| value.checked_mul(BPS))
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        u64::try_from(numerator / denominator).map_err(|_| BojLiquidityError::ArithmeticOverflow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntradayReservation {
    pub reservation_id: [u8; 32],
    pub legal_entity_id: [u8; 32],
    pub instruction_commitment: [u8; 32],
    pub amount_yen: u64,
    pub expires_at: u64,
    pub status: ReservationStatus,
    pub consumed_yen: u64,
}

impl IntradayReservation {
    fn is_live(&self, now: u64) -> bool {
        self.status == ReservationStatus::Active && now < self.expires_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterParticipant {
    pub operation_id: [u8; 32],
    pub participant: BojParticipant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PledgeCollateral {
    pub operation_id: [u8; 32],
    pub expected_participant_sequence: u64,
    pub lot: JgbCollateralLot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevalueCollateral {
    pub operation_id: [u8; 32],
    pub lot_id: [u8; 32],
    pub expected_lot_sequence: u64,
    pub expected_participant_sequence: u64,
    pub market_price_per_100_micros: u64,
    pub index_ratio_ppm: u64,
    pub valuation_rate_bps: u16,
    pub valuation_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReserveIntradayLiquidity {
    pub operation_id: [u8; 32],
    pub reservation_id: [u8; 32],
    pub legal_entity_id: [u8; 32],
    pub instruction_commitment: [u8; 32],
    pub expected_participant_sequence: u64,
    pub amount_yen: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIntradayLiquidity {
    pub operation_id: [u8; 32],
    pub reservation_id: [u8; 32],
    pub legal_entity_id: [u8; 32],
    pub expected_participant_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReturnCollateral {
    pub operation_id: [u8; 32],
    pub lot_id: [u8; 32],
    pub expected_lot_sequence: u64,
    pub expected_participant_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyFundsReceipt {
    pub operation_id: [u8; 32],
    /// Unique identifier of the accepted BOJ current-account credit.  Keeping
    /// this separate from the operation identifier prevents the same external
    /// receipt from being wrapped in two otherwise-valid operations.
    pub receipt_id: [u8; 32],
    pub legal_entity_id: [u8; 32],
    pub expected_participant_sequence: u64,
    pub amount_yen: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FundsReceiptOutcome {
    pub overdraft_repayment_yen: u64,
    pub current_account_balance_after_yen: u64,
    pub intraday_overdraft_after_yen: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateOtherSecuredExposure {
    pub operation_id: [u8; 32],
    pub legal_entity_id: [u8; 32],
    pub expected_participant_sequence: u64,
    pub new_exposure_yen: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenBusinessDay {
    pub operation_id: [u8; 32],
    pub legal_entity_id: [u8; 32],
    pub expected_participant_sequence: u64,
    pub business_day: u32,
    pub repayment_deadline: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimultaneousCollateralDvp {
    pub operation_id: [u8; 32],
    pub settlement_id: [u8; 32],
    pub instruction_commitment: [u8; 32],
    pub buyer_legal_entity_id: [u8; 32],
    pub seller_legal_entity_id: [u8; 32],
    pub lot_id: [u8; 32],
    pub payment_yen: u64,
    pub buyer_pledges_on_receipt: bool,
    /// ZERO means that the received JGB itself may provide the required
    /// headroom.  Otherwise the named pre-reservation is consumed atomically.
    pub overdraft_reservation_id: [u8; 32],
    pub expected_buyer_sequence: u64,
    pub expected_seller_sequence: u64,
    pub expected_lot_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndBusinessDay {
    pub operation_id: [u8; 32],
    pub legal_entity_id: [u8; 32],
    pub expected_participant_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DvpOutcome {
    pub overdraft_draw_yen: u64,
    pub seller_overdraft_repayment_yen: u64,
    pub buyer_cash_after_yen: u64,
    pub seller_cash_after_yen: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BojLiquidityBook {
    pub participants: BTreeMap<String, BojParticipant>,
    pub collateral_lots: BTreeMap<String, JgbCollateralLot>,
    pub reservations: BTreeMap<String, IntradayReservation>,
    pub completed_settlements: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub applied_funds_receipts: BTreeSet<String>,
    pub applied_operations: BTreeSet<String>,
}

impl BojLiquidityBook {
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
            && self.collateral_lots.is_empty()
            && self.reservations.is_empty()
            && self.completed_settlements.is_empty()
            && self.applied_funds_receipts.is_empty()
            && self.applied_operations.is_empty()
    }

    pub fn validate(&self) -> Result<(), BojLiquidityError> {
        for (participant_key, participant) in &self.participants {
            if participant_key != &key(&participant.legal_entity_id)
                || has_zero(&[
                    participant.legal_entity_id,
                    participant.funds_account_id,
                    participant.jgb_account_id,
                ])
                || participant.business_day == 0
                || participant.repayment_deadline == 0
                || (participant.status == ParticipantStatus::Overdue
                    && !participant.business_day_closed)
                || (participant.current_account_balance_yen != 0
                    && participant.intraday_overdraft_yen != 0)
            {
                return Err(BojLiquidityError::InvalidParticipant);
            }
        }
        for (lot_key, lot) in &self.collateral_lots {
            if lot_key != &key(&lot.lot_id)
                || has_zero(&[lot.lot_id, lot.asset_id, lot.owner_legal_entity_id])
                || !self
                    .participants
                    .contains_key(&key(&lot.owner_legal_entity_id))
            {
                return Err(BojLiquidityError::InvalidCollateral);
            }
            lot.collateral_value_yen()?;
        }
        for (reservation_key, reservation) in &self.reservations {
            if reservation_key != &key(&reservation.reservation_id)
                || has_zero(&[
                    reservation.reservation_id,
                    reservation.legal_entity_id,
                    reservation.instruction_commitment,
                ])
                || reservation.amount_yen == 0
                || reservation.expires_at == 0
                || !self
                    .participants
                    .contains_key(&key(&reservation.legal_entity_id))
                || (reservation.status != ReservationStatus::Consumed
                    && reservation.consumed_yen != 0)
                || reservation.consumed_yen > reservation.amount_yen
            {
                return Err(BojLiquidityError::InvalidReservation);
            }
        }
        if self
            .completed_settlements
            .iter()
            .chain(self.applied_funds_receipts.iter())
            .chain(self.applied_operations.iter())
            .any(|value| value.len() != 64 || hex::decode(value).is_err())
        {
            return Err(BojLiquidityError::InvalidStoredState);
        }
        Ok(())
    }

    pub fn register_participant(
        &mut self,
        request: RegisterParticipant,
        now: u64,
    ) -> Result<(), BojLiquidityError> {
        self.atomic(|book| book.register_participant_inner(request, now))
    }

    fn register_participant_inner(
        &mut self,
        request: RegisterParticipant,
        now: u64,
    ) -> Result<(), BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        let participant = request.participant;
        if has_zero(&[
            participant.legal_entity_id,
            participant.funds_account_id,
            participant.jgb_account_id,
        ]) || participant.business_day == 0
            || participant.repayment_deadline <= now
            || participant.sequence != 0
            || participant.intraday_overdraft_yen != 0
            || participant.business_day_closed
            || participant.status != ParticipantStatus::Active
        {
            return Err(BojLiquidityError::InvalidParticipant);
        }
        let participant_key = key(&participant.legal_entity_id);
        if self.participants.contains_key(&participant_key)
            || self.participants.values().any(|existing| {
                existing.funds_account_id == participant.funds_account_id
                    || existing.jgb_account_id == participant.jgb_account_id
            })
        {
            return Err(BojLiquidityError::DuplicateParticipant);
        }
        self.participants.insert(participant_key, participant);
        self.applied_operations.insert(key(&request.operation_id));
        Ok(())
    }

    pub fn pledge_collateral(
        &mut self,
        request: PledgeCollateral,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.atomic(|book| book.pledge_collateral_inner(request, now))
    }

    fn pledge_collateral_inner(
        &mut self,
        request: PledgeCollateral,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        let mut lot = request.lot;
        if has_zero(&[lot.lot_id, lot.asset_id, lot.owner_legal_entity_id])
            || !lot.pledged
            || lot.sequence != 0
            || self.collateral_lots.contains_key(&key(&lot.lot_id))
        {
            return Err(BojLiquidityError::InvalidCollateral);
        }
        let value = lot.collateral_value_yen()?;
        let entity_key = key(&lot.owner_legal_entity_id);
        {
            let participant = self
                .participants
                .get_mut(&entity_key)
                .ok_or(BojLiquidityError::UnknownParticipant)?;
            check_sequence(participant.sequence, request.expected_participant_sequence)?;
            if participant.status == ParticipantStatus::Suspended
                || participant.status == ParticipantStatus::Overdue
                || participant.business_day_closed
                || now >= participant.repayment_deadline
            {
                return Err(BojLiquidityError::ParticipantUnavailable);
            }
            participant.sequence = participant
                .sequence
                .checked_add(1)
                .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        }
        lot.sequence = 1;
        self.collateral_lots.insert(key(&lot.lot_id), lot);
        self.refresh_status_by_key(&entity_key, now)?;
        self.applied_operations.insert(key(&request.operation_id));
        Ok(value)
    }

    pub fn revalue_collateral(
        &mut self,
        request: RevalueCollateral,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.atomic(|book| book.revalue_collateral_inner(request, now))
    }

    fn revalue_collateral_inner(
        &mut self,
        request: RevalueCollateral,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        let lot_key = key(&request.lot_id);
        let entity_id = {
            let lot = self
                .collateral_lots
                .get_mut(&lot_key)
                .ok_or(BojLiquidityError::UnknownCollateral)?;
            check_sequence(lot.sequence, request.expected_lot_sequence)?;
            if request.valuation_epoch <= lot.valuation_epoch {
                return Err(BojLiquidityError::StaleValuation);
            }
            lot.market_price_per_100_micros = request.market_price_per_100_micros;
            lot.index_ratio_ppm = request.index_ratio_ppm;
            lot.valuation_rate_bps = request.valuation_rate_bps;
            lot.valuation_epoch = request.valuation_epoch;
            lot.sequence = lot
                .sequence
                .checked_add(1)
                .ok_or(BojLiquidityError::ArithmeticOverflow)?;
            lot.collateral_value_yen()?;
            lot.owner_legal_entity_id
        };
        let entity_key = key(&entity_id);
        let participant = self
            .participants
            .get_mut(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let total = self.collateral_value(&entity_id)?;
        self.refresh_status_by_key(&entity_key, now)?;
        self.applied_operations.insert(key(&request.operation_id));
        Ok(total)
    }

    pub fn reserve_intraday_liquidity(
        &mut self,
        request: ReserveIntradayLiquidity,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.atomic(|book| book.reserve_intraday_liquidity_inner(request, now))
    }

    fn reserve_intraday_liquidity_inner(
        &mut self,
        request: ReserveIntradayLiquidity,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        if has_zero(&[
            request.reservation_id,
            request.legal_entity_id,
            request.instruction_commitment,
        ]) || request.amount_yen == 0
            || request.expires_at <= now
            || self
                .reservations
                .contains_key(&key(&request.reservation_id))
        {
            return Err(BojLiquidityError::InvalidReservation);
        }
        let entity_key = key(&request.legal_entity_id);
        self.refresh_status_by_key(&entity_key, now)?;
        let participant = self
            .participants
            .get(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        if participant.status != ParticipantStatus::Active
            || participant.business_day_closed
            || request.expires_at > participant.repayment_deadline
            || now >= participant.repayment_deadline
        {
            return Err(BojLiquidityError::ParticipantUnavailable);
        }
        let headroom = self.available_headroom(&request.legal_entity_id, now)?;
        if request.amount_yen > headroom {
            return Err(BojLiquidityError::InsufficientCollateral);
        }
        self.reservations.insert(
            key(&request.reservation_id),
            IntradayReservation {
                reservation_id: request.reservation_id,
                legal_entity_id: request.legal_entity_id,
                instruction_commitment: request.instruction_commitment,
                amount_yen: request.amount_yen,
                expires_at: request.expires_at,
                status: ReservationStatus::Active,
                consumed_yen: 0,
            },
        );
        let participant = self
            .participants
            .get_mut(&entity_key)
            .expect("participant was checked");
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        self.applied_operations.insert(key(&request.operation_id));
        Ok(headroom - request.amount_yen)
    }

    pub fn release_intraday_liquidity(
        &mut self,
        request: ReleaseIntradayLiquidity,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.atomic(|book| book.release_intraday_liquidity_inner(request, now))
    }

    fn release_intraday_liquidity_inner(
        &mut self,
        request: ReleaseIntradayLiquidity,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        let entity_key = key(&request.legal_entity_id);
        let participant = self
            .participants
            .get_mut(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        let reservation = self
            .reservations
            .get_mut(&key(&request.reservation_id))
            .ok_or(BojLiquidityError::UnknownReservation)?;
        if reservation.legal_entity_id != request.legal_entity_id
            || reservation.status != ReservationStatus::Active
        {
            return Err(BojLiquidityError::InvalidReservation);
        }
        reservation.status = ReservationStatus::Released;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        self.refresh_status_by_key(&entity_key, now)?;
        self.applied_operations.insert(key(&request.operation_id));
        self.available_headroom(&request.legal_entity_id, now)
    }

    pub fn return_collateral(
        &mut self,
        request: ReturnCollateral,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.atomic(|book| book.return_collateral_inner(request, now))
    }

    fn return_collateral_inner(
        &mut self,
        request: ReturnCollateral,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        let lot_key = key(&request.lot_id);
        let lot = self
            .collateral_lots
            .get(&lot_key)
            .ok_or(BojLiquidityError::UnknownCollateral)?
            .clone();
        check_sequence(lot.sequence, request.expected_lot_sequence)?;
        if !lot.pledged {
            return Err(BojLiquidityError::InvalidCollateral);
        }
        let entity_key = key(&lot.owner_legal_entity_id);
        self.refresh_status_by_key(&entity_key, now)?;
        let participant = self
            .participants
            .get(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        if participant.status != ParticipantStatus::Active
            || participant.business_day_closed
            || now >= participant.repayment_deadline
        {
            return Err(BojLiquidityError::ParticipantUnavailable);
        }
        let value = lot.collateral_value_yen()?;
        let collateral_after = self
            .collateral_value(&lot.owner_legal_entity_id)?
            .checked_sub(value)
            .ok_or(BojLiquidityError::InvalidStoredState)?;
        let required = participant
            .other_secured_exposure_yen
            .checked_add(participant.intraday_overdraft_yen)
            .and_then(|amount| {
                amount.checked_add(self.live_reserved(&lot.owner_legal_entity_id, now).ok()?)
            })
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        if collateral_after < required {
            return Err(BojLiquidityError::InsufficientCollateral);
        }
        let lot = self
            .collateral_lots
            .get_mut(&lot_key)
            .expect("collateral lot was checked");
        lot.pledged = false;
        lot.sequence = lot
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let participant = self
            .participants
            .get_mut(&entity_key)
            .expect("participant was checked");
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        self.applied_operations.insert(key(&request.operation_id));
        Ok(collateral_after - required)
    }

    pub fn apply_funds_receipt(
        &mut self,
        request: ApplyFundsReceipt,
        now: u64,
    ) -> Result<FundsReceiptOutcome, BojLiquidityError> {
        self.atomic(|book| book.apply_funds_receipt_inner(request, now))
    }

    fn apply_funds_receipt_inner(
        &mut self,
        request: ApplyFundsReceipt,
        now: u64,
    ) -> Result<FundsReceiptOutcome, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        if has_zero(&[request.receipt_id, request.legal_entity_id]) || request.amount_yen == 0 {
            return Err(BojLiquidityError::InvalidFundsReceipt);
        }
        let receipt_key = key(&request.receipt_id);
        if self.applied_funds_receipts.contains(&receipt_key) {
            return Err(BojLiquidityError::DuplicateFundsReceipt);
        }
        let entity_key = key(&request.legal_entity_id);
        let participant = self
            .participants
            .get_mut(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        let repayment = participant.intraday_overdraft_yen.min(request.amount_yen);
        participant.intraday_overdraft_yen -= repayment;
        participant.current_account_balance_yen = participant
            .current_account_balance_yen
            .checked_add(request.amount_yen - repayment)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let outcome = FundsReceiptOutcome {
            overdraft_repayment_yen: repayment,
            current_account_balance_after_yen: participant.current_account_balance_yen,
            intraday_overdraft_after_yen: participant.intraday_overdraft_yen,
        };
        self.refresh_status_by_key(&entity_key, now)?;
        self.applied_funds_receipts.insert(receipt_key);
        self.applied_operations.insert(key(&request.operation_id));
        Ok(outcome)
    }

    pub fn update_other_secured_exposure(
        &mut self,
        request: UpdateOtherSecuredExposure,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.atomic(|book| book.update_other_secured_exposure_inner(request, now))
    }

    fn update_other_secured_exposure_inner(
        &mut self,
        request: UpdateOtherSecuredExposure,
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        if request.legal_entity_id == ZERO {
            return Err(BojLiquidityError::InvalidParticipant);
        }
        let entity_key = key(&request.legal_entity_id);
        let participant = self
            .participants
            .get(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        let required_after = request
            .new_exposure_yen
            .checked_add(participant.intraday_overdraft_yen)
            .and_then(|amount| {
                amount.checked_add(self.live_reserved(&request.legal_entity_id, now).ok()?)
            })
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        if request.new_exposure_yen > participant.other_secured_exposure_yen
            && self.collateral_value(&request.legal_entity_id)? < required_after
        {
            return Err(BojLiquidityError::InsufficientCollateral);
        }
        let participant = self
            .participants
            .get_mut(&entity_key)
            .expect("participant was checked");
        participant.other_secured_exposure_yen = request.new_exposure_yen;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        self.refresh_status_by_key(&entity_key, now)?;
        self.applied_operations.insert(key(&request.operation_id));
        self.available_headroom(&request.legal_entity_id, now)
    }

    pub fn open_business_day(
        &mut self,
        request: OpenBusinessDay,
        now: u64,
    ) -> Result<ParticipantStatus, BojLiquidityError> {
        self.atomic(|book| book.open_business_day_inner(request, now))
    }

    fn open_business_day_inner(
        &mut self,
        request: OpenBusinessDay,
        now: u64,
    ) -> Result<ParticipantStatus, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        let entity_key = key(&request.legal_entity_id);
        let participant = self
            .participants
            .get(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        if participant.status == ParticipantStatus::Suspended
            || participant.intraday_overdraft_yen != 0
            || !participant.business_day_closed
            || request.business_day <= participant.business_day
            || now < participant.repayment_deadline
            || request.repayment_deadline <= now
        {
            return Err(BojLiquidityError::InvalidBusinessDay);
        }
        for reservation in self.reservations.values_mut().filter(|reservation| {
            reservation.legal_entity_id == request.legal_entity_id
                && reservation.status == ReservationStatus::Active
        }) {
            reservation.status = ReservationStatus::Released;
        }
        let participant = self
            .participants
            .get_mut(&entity_key)
            .expect("participant was checked");
        participant.business_day = request.business_day;
        participant.repayment_deadline = request.repayment_deadline;
        participant.business_day_closed = false;
        participant.status = ParticipantStatus::Active;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        self.refresh_status_by_key(&entity_key, now)?;
        let status = self.participants[&entity_key].status;
        self.applied_operations.insert(key(&request.operation_id));
        Ok(status)
    }

    pub fn settle_simultaneous_collateral_dvp(
        &mut self,
        request: SimultaneousCollateralDvp,
        now: u64,
    ) -> Result<DvpOutcome, BojLiquidityError> {
        self.atomic(|book| book.settle_simultaneous_collateral_dvp_inner(request, now))
    }

    fn settle_simultaneous_collateral_dvp_inner(
        &mut self,
        request: SimultaneousCollateralDvp,
        now: u64,
    ) -> Result<DvpOutcome, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        if has_zero(&[
            request.settlement_id,
            request.instruction_commitment,
            request.buyer_legal_entity_id,
            request.seller_legal_entity_id,
            request.lot_id,
        ]) || request.payment_yen == 0
            || request.buyer_legal_entity_id == request.seller_legal_entity_id
            || self
                .completed_settlements
                .contains(&key(&request.settlement_id))
        {
            return Err(BojLiquidityError::InvalidSettlement);
        }
        let buyer_key = key(&request.buyer_legal_entity_id);
        let seller_key = key(&request.seller_legal_entity_id);
        let lot_key = key(&request.lot_id);
        self.refresh_status_by_key(&buyer_key, now)?;
        self.refresh_status_by_key(&seller_key, now)?;
        let buyer = self
            .participants
            .get(&buyer_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?
            .clone();
        let seller = self
            .participants
            .get(&seller_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?
            .clone();
        let lot = self
            .collateral_lots
            .get(&lot_key)
            .ok_or(BojLiquidityError::UnknownCollateral)?
            .clone();
        check_sequence(buyer.sequence, request.expected_buyer_sequence)?;
        check_sequence(seller.sequence, request.expected_seller_sequence)?;
        check_sequence(lot.sequence, request.expected_lot_sequence)?;
        if lot.owner_legal_entity_id != request.seller_legal_entity_id
            || buyer.business_day != seller.business_day
            || now >= buyer.repayment_deadline
            || now >= seller.repayment_deadline
            || buyer.business_day_closed
            || seller.business_day_closed
            || matches!(
                buyer.status,
                ParticipantStatus::Suspended | ParticipantStatus::Overdue
            )
            || matches!(
                seller.status,
                ParticipantStatus::Suspended | ParticipantStatus::Overdue
            )
        {
            return Err(BojLiquidityError::ParticipantUnavailable);
        }

        let draw = request
            .payment_yen
            .saturating_sub(buyer.current_account_balance_yen);
        let seller_repayment = seller.intraday_overdraft_yen.min(request.payment_yen);
        let lot_value = lot.collateral_value_yen()?;

        let mut reserved_by_this = 0;
        if request.overdraft_reservation_id != ZERO {
            let reservation = self
                .reservations
                .get(&key(&request.overdraft_reservation_id))
                .ok_or(BojLiquidityError::UnknownReservation)?;
            if reservation.legal_entity_id != request.buyer_legal_entity_id
                || reservation.instruction_commitment != request.instruction_commitment
                || !reservation.is_live(now)
                || draw > reservation.amount_yen
            {
                return Err(BojLiquidityError::InvalidReservation);
            }
            reserved_by_this = reservation.amount_yen;
        }

        let buyer_collateral_after = self
            .collateral_value(&request.buyer_legal_entity_id)?
            .checked_add(if request.buyer_pledges_on_receipt {
                lot_value
            } else {
                0
            })
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let buyer_other_live_reservations = self
            .live_reserved(&request.buyer_legal_entity_id, now)?
            .checked_sub(reserved_by_this)
            .ok_or(BojLiquidityError::InvalidStoredState)?;
        let buyer_required_after = buyer
            .other_secured_exposure_yen
            .checked_add(buyer.intraday_overdraft_yen)
            .and_then(|value| value.checked_add(draw))
            .and_then(|value| value.checked_add(buyer_other_live_reservations))
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        if draw != 0 && buyer.status != ParticipantStatus::Active {
            return Err(BojLiquidityError::ParticipantUnavailable);
        }
        if buyer_collateral_after < buyer_required_after {
            return Err(BojLiquidityError::InsufficientCollateral);
        }

        let seller_collateral_after = self
            .collateral_value(&request.seller_legal_entity_id)?
            .checked_sub(if lot.pledged { lot_value } else { 0 })
            .ok_or(BojLiquidityError::InvalidStoredState)?;
        let seller_required_after = seller
            .other_secured_exposure_yen
            .checked_add(seller.intraday_overdraft_yen - seller_repayment)
            .and_then(|value| {
                value.checked_add(
                    self.live_reserved(&request.seller_legal_entity_id, now)
                        .ok()?,
                )
            })
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        if seller_collateral_after < seller_required_after {
            return Err(BojLiquidityError::InsufficientCollateral);
        }

        let buyer_cash_after = buyer
            .current_account_balance_yen
            .checked_add(draw)
            .and_then(|value| value.checked_sub(request.payment_yen))
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let seller_cash_after = seller
            .current_account_balance_yen
            .checked_add(request.payment_yen - seller_repayment)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;

        {
            let buyer = self
                .participants
                .get_mut(&buyer_key)
                .expect("buyer was checked");
            buyer.current_account_balance_yen = buyer_cash_after;
            buyer.intraday_overdraft_yen = buyer
                .intraday_overdraft_yen
                .checked_add(draw)
                .ok_or(BojLiquidityError::ArithmeticOverflow)?;
            buyer.sequence = buyer
                .sequence
                .checked_add(1)
                .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        }
        {
            let seller = self
                .participants
                .get_mut(&seller_key)
                .expect("seller was checked");
            seller.current_account_balance_yen = seller_cash_after;
            seller.intraday_overdraft_yen -= seller_repayment;
            seller.sequence = seller
                .sequence
                .checked_add(1)
                .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        }
        {
            let lot = self
                .collateral_lots
                .get_mut(&lot_key)
                .expect("lot was checked");
            lot.owner_legal_entity_id = request.buyer_legal_entity_id;
            lot.pledged = request.buyer_pledges_on_receipt;
            lot.sequence = lot
                .sequence
                .checked_add(1)
                .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        }
        if request.overdraft_reservation_id != ZERO {
            let reservation = self
                .reservations
                .get_mut(&key(&request.overdraft_reservation_id))
                .expect("reservation was checked");
            reservation.status = ReservationStatus::Consumed;
            reservation.consumed_yen = draw;
        }
        self.refresh_status_by_key(&buyer_key, now)?;
        self.refresh_status_by_key(&seller_key, now)?;
        self.completed_settlements
            .insert(key(&request.settlement_id));
        self.applied_operations.insert(key(&request.operation_id));
        Ok(DvpOutcome {
            overdraft_draw_yen: draw,
            seller_overdraft_repayment_yen: seller_repayment,
            buyer_cash_after_yen: buyer_cash_after,
            seller_cash_after_yen: seller_cash_after,
        })
    }

    pub fn end_business_day(
        &mut self,
        request: EndBusinessDay,
        now: u64,
    ) -> Result<ParticipantStatus, BojLiquidityError> {
        self.atomic(|book| book.end_business_day_inner(request, now))
    }

    fn end_business_day_inner(
        &mut self,
        request: EndBusinessDay,
        now: u64,
    ) -> Result<ParticipantStatus, BojLiquidityError> {
        self.ensure_new_operation(request.operation_id)?;
        let entity_key = key(&request.legal_entity_id);
        let participant = self
            .participants
            .get_mut(&entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        check_sequence(participant.sequence, request.expected_participant_sequence)?;
        if now < participant.repayment_deadline {
            return Err(BojLiquidityError::TooEarlyForEndOfDay);
        }
        if participant.business_day_closed {
            return Err(BojLiquidityError::BusinessDayAlreadyClosed);
        }
        for reservation in self.reservations.values_mut().filter(|reservation| {
            reservation.legal_entity_id == request.legal_entity_id
                && reservation.status == ReservationStatus::Active
        }) {
            reservation.status = ReservationStatus::Released;
        }
        participant.status = if participant.intraday_overdraft_yen == 0 {
            ParticipantStatus::Active
        } else {
            ParticipantStatus::Overdue
        };
        participant.business_day_closed = true;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let status = participant.status;
        self.applied_operations.insert(key(&request.operation_id));
        Ok(status)
    }

    pub fn collateral_value(&self, entity_id: &[u8; 32]) -> Result<u64, BojLiquidityError> {
        self.collateral_lots
            .values()
            .filter(|lot| lot.owner_legal_entity_id == *entity_id && lot.pledged)
            .try_fold(0u64, |total, lot| {
                total
                    .checked_add(lot.collateral_value_yen()?)
                    .ok_or(BojLiquidityError::ArithmeticOverflow)
            })
    }

    pub fn live_reserved(&self, entity_id: &[u8; 32], now: u64) -> Result<u64, BojLiquidityError> {
        self.reservations
            .values()
            .filter(|reservation| {
                reservation.legal_entity_id == *entity_id && reservation.is_live(now)
            })
            .try_fold(0u64, |total, reservation| {
                total
                    .checked_add(reservation.amount_yen)
                    .ok_or(BojLiquidityError::ArithmeticOverflow)
            })
    }

    pub fn available_headroom(
        &self,
        entity_id: &[u8; 32],
        now: u64,
    ) -> Result<u64, BojLiquidityError> {
        let participant = self
            .participants
            .get(&key(entity_id))
            .ok_or(BojLiquidityError::UnknownParticipant)?;
        let required = participant
            .other_secured_exposure_yen
            .checked_add(participant.intraday_overdraft_yen)
            .and_then(|value| value.checked_add(self.live_reserved(entity_id, now).ok()?))
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        Ok(self.collateral_value(entity_id)?.saturating_sub(required))
    }

    fn refresh_status_by_key(
        &mut self,
        entity_key: &str,
        now: u64,
    ) -> Result<(), BojLiquidityError> {
        let entity_id = self
            .participants
            .get(entity_key)
            .ok_or(BojLiquidityError::UnknownParticipant)?
            .legal_entity_id;
        let collateral = self.collateral_value(&entity_id)?;
        let participant = self
            .participants
            .get(entity_key)
            .expect("participant was checked");
        let required = participant
            .other_secured_exposure_yen
            .checked_add(participant.intraday_overdraft_yen)
            .and_then(|value| value.checked_add(self.live_reserved(&entity_id, now).ok()?))
            .ok_or(BojLiquidityError::ArithmeticOverflow)?;
        let participant = self
            .participants
            .get_mut(entity_key)
            .expect("participant was checked");
        if participant.status != ParticipantStatus::Suspended
            && participant.status != ParticipantStatus::Overdue
        {
            participant.status = if collateral < required {
                ParticipantStatus::CollateralShortfall
            } else {
                ParticipantStatus::Active
            };
        }
        Ok(())
    }

    fn ensure_new_operation(&self, operation_id: [u8; 32]) -> Result<(), BojLiquidityError> {
        if operation_id == ZERO {
            return Err(BojLiquidityError::InvalidOperation);
        }
        if self.applied_operations.contains(&key(&operation_id)) {
            return Err(BojLiquidityError::DuplicateOperation);
        }
        Ok(())
    }

    fn atomic<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, BojLiquidityError>,
    ) -> Result<T, BojLiquidityError> {
        let mut next = self.clone();
        let result = operation(&mut next)?;
        next.validate()?;
        *self = next;
        Ok(result)
    }
}

pub fn operation_statement<T: Serialize>(
    operation: &[u8],
    request: &T,
) -> Result<[u8; 32], String> {
    let encoded = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    let mut hash = Sha256::new();
    hash.update(b"QOMM:DEFMI:BOJ-LIQUIDITY:v1");
    hash.update((operation.len() as u64).to_be_bytes());
    hash.update(operation);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn key(value: &[u8; 32]) -> String {
    hex::encode(value)
}

fn has_zero(values: &[[u8; 32]]) -> bool {
    values.contains(&ZERO)
}

fn check_sequence(actual: u64, expected: u64) -> Result<(), BojLiquidityError> {
    if actual != expected {
        return Err(BojLiquidityError::StaleSequence);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BojLiquidityError {
    #[error("invalid BOJ liquidity operation")]
    InvalidOperation,
    #[error("operation identifier was already used")]
    DuplicateOperation,
    #[error("invalid BOJ participant")]
    InvalidParticipant,
    #[error("participant already exists")]
    DuplicateParticipant,
    #[error("unknown BOJ participant")]
    UnknownParticipant,
    #[error("participant cannot receive new intraday credit")]
    ParticipantUnavailable,
    #[error("invalid JGB collateral")]
    InvalidCollateral,
    #[error("unknown JGB collateral")]
    UnknownCollateral,
    #[error("collateral valuation is stale")]
    StaleValuation,
    #[error("invalid intraday liquidity reservation")]
    InvalidReservation,
    #[error("unknown intraday liquidity reservation")]
    UnknownReservation,
    #[error("invalid BOJ current-account funds receipt")]
    InvalidFundsReceipt,
    #[error("BOJ current-account funds receipt was already applied")]
    DuplicateFundsReceipt,
    #[error("collateral surplus is insufficient")]
    InsufficientCollateral,
    #[error("invalid simultaneous collateral DvP")]
    InvalidSettlement,
    #[error("expected sequence does not match authoritative state")]
    StaleSequence,
    #[error("business-day close was requested before the repayment deadline")]
    TooEarlyForEndOfDay,
    #[error("BOJ business day was already closed")]
    BusinessDayAlreadyClosed,
    #[error("invalid BOJ business-day transition")]
    InvalidBusinessDay,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("stored BOJ liquidity state is invalid")]
    InvalidStoredState,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn participant(entity: u8, cash: u64, deadline: u64) -> BojParticipant {
        BojParticipant {
            legal_entity_id: id(entity),
            funds_account_id: id(entity + 10),
            jgb_account_id: id(entity + 20),
            current_account_balance_yen: cash,
            other_secured_exposure_yen: 0,
            intraday_overdraft_yen: 0,
            business_day: 20260831,
            repayment_deadline: deadline,
            business_day_closed: false,
            sequence: 0,
            status: ParticipantStatus::Active,
        }
    }

    fn lot(owner: u8, lot: u8, face: u64, pledged: bool) -> JgbCollateralLot {
        JgbCollateralLot {
            lot_id: id(lot),
            asset_id: id(90),
            owner_legal_entity_id: id(owner),
            face_value_yen: face,
            market_price_per_100_micros: 100_000_000,
            index_ratio_ppm: 1_000_000,
            valuation_rate_bps: 9_700,
            valuation_epoch: 1,
            pledged,
            sequence: 0,
        }
    }

    fn register(book: &mut BojLiquidityBook, entity: u8, cash: u64) {
        book.register_participant(
            RegisterParticipant {
                operation_id: id(entity + 100),
                participant: participant(entity, cash, 10_000),
            },
            100,
        )
        .expect("register participant");
    }

    #[test]
    fn values_jgb_using_price_index_and_boj_valuation_rate() {
        let mut indexed = lot(1, 3, 1_000_000, true);
        indexed.market_price_per_100_micros = 102_500_000;
        indexed.index_ratio_ppm = 1_020_000;
        indexed.valuation_rate_bps = 9_600;
        assert_eq!(indexed.collateral_value_yen().unwrap(), 1_003_680);
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_entity_wide_surplus() {
        let mut book = BojLiquidityBook::default();
        register(&mut book, 1, 0);
        book.pledge_collateral(
            PledgeCollateral {
                operation_id: id(40),
                expected_participant_sequence: 0,
                lot: lot(1, 30, 1_000_000, true),
            },
            100,
        )
        .unwrap();
        assert_eq!(book.available_headroom(&id(1), 100).unwrap(), 970_000);
        book.reserve_intraday_liquidity(
            ReserveIntradayLiquidity {
                operation_id: id(41),
                reservation_id: id(50),
                legal_entity_id: id(1),
                instruction_commitment: id(60),
                expected_participant_sequence: 1,
                amount_yen: 700_000,
                expires_at: 1_000,
            },
            100,
        )
        .unwrap();
        let stale = book.reserve_intraday_liquidity(
            ReserveIntradayLiquidity {
                operation_id: id(42),
                reservation_id: id(51),
                legal_entity_id: id(1),
                instruction_commitment: id(61),
                expected_participant_sequence: 1,
                amount_yen: 100_000,
                expires_at: 1_000,
            },
            100,
        );
        assert_eq!(stale.unwrap_err(), BojLiquidityError::StaleSequence);
        let over = book.reserve_intraday_liquidity(
            ReserveIntradayLiquidity {
                operation_id: id(43),
                reservation_id: id(52),
                legal_entity_id: id(1),
                instruction_commitment: id(62),
                expected_participant_sequence: 2,
                amount_yen: 300_000,
                expires_at: 1_000,
            },
            100,
        );
        assert_eq!(over.unwrap_err(), BojLiquidityError::InsufficientCollateral);
    }

    #[test]
    fn receipt_pledge_draw_payment_and_seller_repayment_are_atomic() {
        let mut book = BojLiquidityBook::default();
        register(&mut book, 1, 100_000);
        register(&mut book, 2, 0);
        let mut seller_lot = lot(2, 30, 1_000_000, true);
        seller_lot.sequence = 1;
        book.collateral_lots
            .insert(key(&seller_lot.lot_id), seller_lot);
        book.participants
            .get_mut(&key(&id(2)))
            .unwrap()
            .intraday_overdraft_yen = 400_000;

        let outcome = book
            .settle_simultaneous_collateral_dvp(
                SimultaneousCollateralDvp {
                    operation_id: id(70),
                    settlement_id: id(71),
                    instruction_commitment: id(72),
                    buyer_legal_entity_id: id(1),
                    seller_legal_entity_id: id(2),
                    lot_id: id(30),
                    payment_yen: 800_000,
                    buyer_pledges_on_receipt: true,
                    overdraft_reservation_id: ZERO,
                    expected_buyer_sequence: 0,
                    expected_seller_sequence: 0,
                    expected_lot_sequence: 1,
                },
                100,
            )
            .unwrap();
        assert_eq!(outcome.overdraft_draw_yen, 700_000);
        assert_eq!(outcome.seller_overdraft_repayment_yen, 400_000);
        assert_eq!(outcome.buyer_cash_after_yen, 0);
        assert_eq!(outcome.seller_cash_after_yen, 400_000);
        assert_eq!(book.collateral_value(&id(1)).unwrap(), 970_000);
        assert_eq!(book.collateral_value(&id(2)).unwrap(), 0);
        assert_eq!(
            book.participants[&key(&id(1))].intraday_overdraft_yen,
            700_000
        );
        assert_eq!(book.participants[&key(&id(2))].intraday_overdraft_yen, 0);
        assert_eq!(
            book.collateral_lots[&key(&id(30))].owner_legal_entity_id,
            id(1)
        );
        book.validate().unwrap();
    }

    #[test]
    fn failed_atomic_dvp_leaves_every_record_unchanged() {
        let mut book = BojLiquidityBook::default();
        register(&mut book, 1, 0);
        register(&mut book, 2, 0);
        let mut seller_lot = lot(2, 30, 100_000, true);
        seller_lot.sequence = 1;
        book.collateral_lots
            .insert(key(&seller_lot.lot_id), seller_lot);
        let before = book.clone();
        let error = book
            .settle_simultaneous_collateral_dvp(
                SimultaneousCollateralDvp {
                    operation_id: id(80),
                    settlement_id: id(81),
                    instruction_commitment: id(82),
                    buyer_legal_entity_id: id(1),
                    seller_legal_entity_id: id(2),
                    lot_id: id(30),
                    payment_yen: 200_000,
                    buyer_pledges_on_receipt: true,
                    overdraft_reservation_id: ZERO,
                    expected_buyer_sequence: 0,
                    expected_seller_sequence: 0,
                    expected_lot_sequence: 1,
                },
                100,
            )
            .unwrap_err();
        assert_eq!(error, BojLiquidityError::InsufficientCollateral);
        assert_eq!(book, before);
    }

    #[test]
    fn revaluation_shortfall_blocks_new_credit_and_eod_marks_overdue() {
        let mut book = BojLiquidityBook::default();
        register(&mut book, 1, 0);
        book.pledge_collateral(
            PledgeCollateral {
                operation_id: id(90),
                expected_participant_sequence: 0,
                lot: lot(1, 30, 1_000_000, true),
            },
            100,
        )
        .unwrap();
        {
            let participant = book.participants.get_mut(&key(&id(1))).unwrap();
            participant.intraday_overdraft_yen = 900_000;
        }
        book.revalue_collateral(
            RevalueCollateral {
                operation_id: id(91),
                lot_id: id(30),
                expected_lot_sequence: 1,
                expected_participant_sequence: 1,
                market_price_per_100_micros: 80_000_000,
                index_ratio_ppm: 1_000_000,
                valuation_rate_bps: 9_000,
                valuation_epoch: 2,
            },
            200,
        )
        .unwrap();
        assert_eq!(
            book.participants[&key(&id(1))].status,
            ParticipantStatus::CollateralShortfall
        );
        let result = book.reserve_intraday_liquidity(
            ReserveIntradayLiquidity {
                operation_id: id(92),
                reservation_id: id(93),
                legal_entity_id: id(1),
                instruction_commitment: id(94),
                expected_participant_sequence: 2,
                amount_yen: 1,
                expires_at: 1_000,
            },
            200,
        );
        assert_eq!(
            result.unwrap_err(),
            BojLiquidityError::ParticipantUnavailable
        );
        assert_eq!(
            book.end_business_day(
                EndBusinessDay {
                    operation_id: id(95),
                    legal_entity_id: id(1),
                    expected_participant_sequence: 2,
                },
                10_000,
            )
            .unwrap(),
            ParticipantStatus::Overdue
        );
    }

    #[test]
    fn expired_reservation_can_cure_a_temporary_shortfall() {
        let mut book = BojLiquidityBook::default();
        register(&mut book, 1, 0);
        book.pledge_collateral(
            PledgeCollateral {
                operation_id: id(110),
                expected_participant_sequence: 0,
                lot: lot(1, 30, 1_000_000, true),
            },
            100,
        )
        .unwrap();
        book.reserve_intraday_liquidity(
            ReserveIntradayLiquidity {
                operation_id: id(111),
                reservation_id: id(50),
                legal_entity_id: id(1),
                instruction_commitment: id(60),
                expected_participant_sequence: 1,
                amount_yen: 900_000,
                expires_at: 150,
            },
            100,
        )
        .unwrap();
        book.revalue_collateral(
            RevalueCollateral {
                operation_id: id(112),
                lot_id: id(30),
                expected_lot_sequence: 1,
                expected_participant_sequence: 2,
                market_price_per_100_micros: 80_000_000,
                index_ratio_ppm: 1_000_000,
                valuation_rate_bps: 9_000,
                valuation_epoch: 2,
            },
            120,
        )
        .unwrap();
        assert_eq!(
            book.participants[&key(&id(1))].status,
            ParticipantStatus::CollateralShortfall
        );
        assert_eq!(
            book.reserve_intraday_liquidity(
                ReserveIntradayLiquidity {
                    operation_id: id(113),
                    reservation_id: id(51),
                    legal_entity_id: id(1),
                    instruction_commitment: id(61),
                    expected_participant_sequence: 3,
                    amount_yen: 100_000,
                    expires_at: 300,
                },
                200,
            )
            .unwrap(),
            620_000
        );
        assert_eq!(
            book.participants[&key(&id(1))].status,
            ParticipantStatus::Active
        );
    }

    #[test]
    fn collateral_return_respects_all_other_common_collateral_uses() {
        let mut book = BojLiquidityBook::default();
        register(&mut book, 1, 0);
        book.pledge_collateral(
            PledgeCollateral {
                operation_id: id(120),
                expected_participant_sequence: 0,
                lot: lot(1, 30, 1_000_000, true),
            },
            100,
        )
        .unwrap();
        book.update_other_secured_exposure(
            UpdateOtherSecuredExposure {
                operation_id: id(121),
                legal_entity_id: id(1),
                expected_participant_sequence: 1,
                new_exposure_yen: 600_000,
            },
            100,
        )
        .unwrap();
        let before = book.clone();
        assert_eq!(
            book.return_collateral(
                ReturnCollateral {
                    operation_id: id(122),
                    lot_id: id(30),
                    expected_lot_sequence: 1,
                    expected_participant_sequence: 2,
                },
                100,
            )
            .unwrap_err(),
            BojLiquidityError::InsufficientCollateral
        );
        assert_eq!(book, before);
        book.update_other_secured_exposure(
            UpdateOtherSecuredExposure {
                operation_id: id(123),
                legal_entity_id: id(1),
                expected_participant_sequence: 2,
                new_exposure_yen: 0,
            },
            100,
        )
        .unwrap();
        assert_eq!(
            book.return_collateral(
                ReturnCollateral {
                    operation_id: id(124),
                    lot_id: id(30),
                    expected_lot_sequence: 1,
                    expected_participant_sequence: 3,
                },
                100,
            )
            .unwrap(),
            0
        );
        assert!(!book.collateral_lots[&key(&id(30))].pledged);
    }

    #[test]
    fn accepted_funds_repay_overdraft_once_and_enable_the_next_business_day() {
        let mut book = BojLiquidityBook::default();
        register(&mut book, 1, 0);
        book.participants
            .get_mut(&key(&id(1)))
            .unwrap()
            .intraday_overdraft_yen = 500_000;
        let first = book
            .apply_funds_receipt(
                ApplyFundsReceipt {
                    operation_id: id(125),
                    receipt_id: id(126),
                    legal_entity_id: id(1),
                    expected_participant_sequence: 0,
                    amount_yen: 400_000,
                },
                9_000,
            )
            .unwrap();
        assert_eq!(first.overdraft_repayment_yen, 400_000);
        assert_eq!(first.intraday_overdraft_after_yen, 100_000);
        let before_replay = book.clone();
        assert_eq!(
            book.apply_funds_receipt(
                ApplyFundsReceipt {
                    operation_id: id(127),
                    receipt_id: id(126),
                    legal_entity_id: id(1),
                    expected_participant_sequence: 1,
                    amount_yen: 400_000,
                },
                9_000,
            )
            .unwrap_err(),
            BojLiquidityError::DuplicateFundsReceipt
        );
        assert_eq!(book, before_replay);
        assert_eq!(
            book.end_business_day(
                EndBusinessDay {
                    operation_id: id(128),
                    legal_entity_id: id(1),
                    expected_participant_sequence: 1,
                },
                10_000,
            )
            .unwrap(),
            ParticipantStatus::Overdue
        );
        let after_close = book.clone();
        assert_eq!(
            book.end_business_day(
                EndBusinessDay {
                    operation_id: id(132),
                    legal_entity_id: id(1),
                    expected_participant_sequence: 2,
                },
                10_001,
            )
            .unwrap_err(),
            BojLiquidityError::BusinessDayAlreadyClosed
        );
        assert_eq!(book, after_close);
        let final_receipt = book
            .apply_funds_receipt(
                ApplyFundsReceipt {
                    operation_id: id(129),
                    receipt_id: id(130),
                    legal_entity_id: id(1),
                    expected_participant_sequence: 2,
                    amount_yen: 200_000,
                },
                10_001,
            )
            .unwrap();
        assert_eq!(final_receipt.overdraft_repayment_yen, 100_000);
        assert_eq!(final_receipt.current_account_balance_after_yen, 100_000);
        assert_eq!(
            book.open_business_day(
                OpenBusinessDay {
                    operation_id: id(131),
                    legal_entity_id: id(1),
                    expected_participant_sequence: 3,
                    business_day: 20260901,
                    repayment_deadline: 20_000,
                },
                10_001,
            )
            .unwrap(),
            ParticipantStatus::Active
        );
    }
}
