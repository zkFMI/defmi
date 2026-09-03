//! MP-SPDZ as a library.
//!
//! The measurements this replaces were taken by launching a party binary and
//! matching regular expressions against what it printed. That works until the
//! wording changes, and it cannot see anything the binary does not choose to
//! print. The engine already keeps every round and every byte in a structure;
//! this reads that structure.
//!
//! What is deliberately not attempted: reimplementing the protocol. The
//! malicious-security machinery --- the MACs, the sacrificing, the verification
//! --- is what makes the overhead figure mean anything, and a reimplementation
//! would replace a number about a mature engine with a number about this crate.
//! The engine stays; only the way its results are read changes.
//!
//! The crate builds without MP-SPDZ present, in which case [`available`] is
//! false and [`run`] returns [`Error::EngineAbsent`]. Most machines do not have
//! a checkout, and a workspace that will not compile without one is worse than
//! one that says so.

pub mod compiler;
pub mod inputs;
pub mod persistence;
pub mod program;

#[cfg(have_spdz)]
use std::ffi::{CStr, CString};
#[cfg(have_spdz)]
use std::os::raw::{c_char, c_int};

/// Which protocol to run the circuit under.
///
/// Both are honest-majority Shamir over the same field and the same program;
/// they differ in whether a corrupted party can deviate without being caught.
/// Measuring the pair is what turns "malicious security costs X" from an
/// assertion into a ratio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    MaliciousShamir,
    SemiHonestShamir,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::MaliciousShamir => "malicious-shamir",
            Protocol::SemiHonestShamir => "semi-honest-shamir",
        }
    }

    pub fn parse(name: &str) -> Option<Protocol> {
        [Protocol::MaliciousShamir, Protocol::SemiHonestShamir]
            .into_iter()
            .find(|p| p.as_str() == name)
    }

    /// The party binary a reader would have run instead, so a result can be
    /// checked against the stock tool without having to remember the pairing.
    pub fn stock_binary(&self) -> &'static str {
        match self {
            Protocol::MaliciousShamir => "malicious-shamir-party.x",
            Protocol::SemiHonestShamir => "shamir-party.x",
        }
    }
}

/// One named communication channel, so a reader can see *where* the rounds went
/// rather than only how many there were --- which is the whole argument about
/// depth against width.
#[derive(Clone, Debug)]
pub struct Channel {
    pub name: String,
    pub rounds: u64,
    pub bytes: u64,
}

/// What one run cost, as the machine itself counted it.
///
/// The two byte counts are two different true things. [`Run::sent`] is what this
/// party put on the wire, so a message broadcast to six peers counts six times;
/// it is the figure MP-SPDZ prints as "Data sent". [`Run::payload`] sums the
/// per-channel counts, where the same message counts once. Their ratio is the
/// average fan-out of a message.
///
/// [`Run::rounds`] excludes channels whose name mentions transmission, which is
/// what `BaseMachine::print_comm` excludes; [`Run::raw_rounds`] excludes
/// nothing. Keeping both is what lets a number read this way be compared with a
/// number read off a log without either side having to guess.
#[derive(Clone, Debug)]
pub struct Run {
    pub protocol: Protocol,
    pub rounds: u64,
    pub raw_rounds: u64,
    pub sent: u64,
    pub payload: u64,
    pub seconds: f64,
    pub channels: Vec<Channel>,
}

#[derive(Debug)]
pub enum Error {
    /// Built without MP-SPDZ. Set `MP_SPDZ_ROOT` and rebuild.
    EngineAbsent,
    /// The machine raised, and this is what it said.
    Engine(String),
    /// An argument could not be handed across the boundary.
    BadArgument(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EngineAbsent => write!(
                f,
                "built without MP-SPDZ; set MP_SPDZ_ROOT to a checkout with libSPDZ"
            ),
            Error::Engine(why) => write!(f, "the machine failed: {why}"),
            Error::BadArgument(why) => write!(f, "bad argument: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether this build can run anything.
pub const fn available() -> bool {
    cfg!(have_spdz)
}

#[cfg(have_spdz)]
const MAX_CHANNELS: usize = 64;

#[cfg(have_spdz)]
#[repr(C)]
struct CRun {
    ok: c_int,
    rounds: u64,
    raw_rounds: u64,
    sent: u64,
    payload: u64,
    seconds: f64,
    error: [c_char; 256],
}

#[cfg(have_spdz)]
#[repr(C)]
#[derive(Clone, Copy)]
struct CChannel {
    name: [c_char; 64],
    rounds: u64,
    bytes: u64,
}

#[cfg(have_spdz)]
unsafe extern "C" {
    fn qomm_run_malicious_shamir(
        argc: c_int,
        argv: *const *const c_char,
        channels: *mut CChannel,
        capacity: c_int,
        written: *mut c_int,
    ) -> CRun;
    fn qomm_run_semi_honest_shamir(
        argc: c_int,
        argv: *const *const c_char,
        channels: *mut CChannel,
        capacity: c_int,
        written: *mut c_int,
    ) -> CRun;
}

/// Run one compiled program under one protocol.
///
/// `args` are the party binary's own arguments, unchanged --- so a call here and
/// a call to `malicious-shamir-party.x` differ in how the result is read and in
/// nothing else.
pub fn run(protocol: Protocol, args: &[&str]) -> Result<Run, Error> {
    #[cfg(not(have_spdz))]
    {
        let _ = (protocol, args);
        Err(Error::EngineAbsent)
    }
    #[cfg(have_spdz)]
    {
        let owned: Vec<CString> = args
            .iter()
            .map(|a| CString::new(*a).map_err(|e| Error::BadArgument(e.to_string())))
            .collect::<Result<_, _>>()?;
        let pointers: Vec<*const c_char> = owned.iter().map(|s| s.as_ptr()).collect();

        let mut channels = [CChannel {
            name: [0; 64],
            rounds: 0,
            bytes: 0,
        }; MAX_CHANNELS];
        let mut written: c_int = 0;
        let raw = unsafe {
            let call = match protocol {
                Protocol::MaliciousShamir => qomm_run_malicious_shamir,
                Protocol::SemiHonestShamir => qomm_run_semi_honest_shamir,
            };
            call(
                pointers.len() as c_int,
                pointers.as_ptr(),
                channels.as_mut_ptr(),
                MAX_CHANNELS as c_int,
                &mut written,
            )
        };
        if raw.ok != 0 {
            let why = unsafe { CStr::from_ptr(raw.error.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(Error::Engine(why));
        }
        let channels = channels[..written.max(0) as usize]
            .iter()
            .map(|c| Channel {
                name: unsafe { CStr::from_ptr(c.name.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
                rounds: c.rounds,
                bytes: c.bytes,
            })
            .collect();
        Ok(Run {
            protocol,
            rounds: raw.rounds,
            raw_rounds: raw.raw_rounds,
            sent: raw.sent,
            payload: raw.payload,
            seconds: raw.seconds,
            channels,
        })
    }
}
