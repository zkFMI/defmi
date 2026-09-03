//! DeFMI: settlement that cannot read what it settles.
// SQLite stores consensus timestamps as signed INTEGER values. Keep every
// cross-runtime statement inside the same representable Unix-second domain.
pub(crate) const MAX_UNIX_TIME: u64 = i64::MAX as u64;

pub mod asset_link;
pub mod assets;
#[cfg(feature = "avalanche")]
pub mod avalanche;
pub mod ccp;
pub mod central_bank_liquidity;
pub mod chain;
pub mod credit;
pub mod cross_domain;
pub mod cross_domain_finality;
#[cfg(feature = "avalanche")]
pub mod facility;
pub mod ledger;
pub mod netting;
#[cfg(feature = "avalanche")]
pub mod note_chain;
pub mod note_settlement;
pub mod notes;
pub mod participant;
#[cfg(feature = "avalanche")]
pub mod product;
pub mod product_evidence;
pub mod pvp;
pub mod reconcile;
pub mod register;
pub mod settlement;
pub mod settlement_verifier;
pub mod vetting;
pub mod viewing;
