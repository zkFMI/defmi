// A C entry point into MP-SPDZ, so a caller reads the run's statistics from the
// machine instead of from its stdout.
//
// The measurements this replaces were taken by launching a party binary and
// matching regular expressions against what it printed. That works until the
// wording changes, and it cannot see anything the binary does not choose to
// print --- per-channel round counts among them. MP-SPDZ already keeps all of it
// in `BaseMachine::singleton->comm_stats`, so the shim runs the same machine the
// binary runs and then reads the structure.
//
// Only C linkage crosses the boundary. Everything with a C++ type stays on this
// side, which is what lets the Rust caller be an ordinary FFI consumer rather
// than something that has to know MP-SPDZ's headers.

#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "Protocols/MaliciousShamirShare.h"
#include "Protocols/ShamirShare.h"
#include "Protocols/ShamirOptions.h"
#include "Processor/BaseMachine.h"
#include "Machines/MalRep.hpp"
#include "Processor/FieldMachine.h"
#include "Processor/HonestMajorityMachine.h"
#include "Machines/Shamir.hpp"

extern "C" {

/// What one run cost, as the machine itself counted it.
///
/// `sent` and `payload` are two different true things and the difference is not
/// rounding. `sent` is what this party put on the wire, so a message broadcast
/// to six peers is counted six times; `payload` is the sum of the per-channel
/// byte counts, where that message is counted once. MP-SPDZ prints the first
/// and keeps the second. The ratio between them is the average fan-out of a
/// message, which is a fact about the protocol worth having.
struct QommRun {
    int ok;                     // 0 on success
    unsigned long long rounds;  // as MP-SPDZ counts them: transmission excluded
    unsigned long long raw_rounds;   // every channel, including transmission
    unsigned long long sent;    // bytes this party put on the wire
    unsigned long long payload; // per-channel bytes, each message counted once
    double seconds;             // wall time inside the machine
    char error[256];
};

/// One named communication channel, so a caller can see where the rounds went
/// rather than only how many there were.
struct QommChannel {
    char name[64];
    unsigned long long rounds;
    unsigned long long bytes;
};

}  // extern "C"

namespace {

// `BaseMachine::comm_stats` is protected and the class offers no accessor, only
// `print_comm`, which prints --- the very thing this shim exists to stop doing.
// Rather than patch MP-SPDZ (which would make the measurement no longer one of
// stock MP-SPDZ), the member is reached through the one route the standard
// blesses: access checks are not applied to the template arguments of an
// explicit instantiation, so instantiating with the member pointer is legal and
// the injected friend it defines is an ordinary function afterwards.
template <auto Member>
struct StatsAccess {
    friend const NamedCommStats& comm_stats_of(const BaseMachine& machine) {
        return machine.*Member;
    }
};
const NamedCommStats& comm_stats_of(const BaseMachine& machine);
template struct StatsAccess<&BaseMachine::comm_stats>;

/// Where the hook leaves what it saw.
///
/// The machine is a temporary deep inside MP-SPDZ and is destroyed the moment
/// its run returns, so the statistics have to be copied out from inside rather
/// than read from outside. `capture_after_run` below is registered with the
/// patched engine, which calls it while the machine is still alive; everything
/// else is stock.
struct Captured {
    bool seen = false;
    unsigned long long rounds = 0;
    unsigned long long raw_rounds = 0;
    unsigned long long sent = 0;
    unsigned long long payload = 0;
    double seconds = 0;
    std::vector<std::pair<std::string, std::pair<unsigned long long, unsigned long long>>>
        channels;
};

Captured captured;

}  // namespace

void capture_after_run(const BaseMachine* machine) {
    captured = Captured{};
    if (!machine) return;
    const NamedCommStats& stats = comm_stats_of(*machine);
    for (const auto& entry : stats) {
        captured.raw_rounds += entry.second.rounds;
        // `BaseMachine::print_comm` leaves transmission channels out of the
        // round count it prints. The count here has to be the same count, or a
        // number taken this way and a number taken from a log would silently be
        // two different quantities with one name.
        if (entry.first.find("transmission") == std::string::npos)
            captured.rounds += entry.second.rounds;
        captured.payload += entry.second.data;
        captured.channels.push_back(
            {entry.first, {entry.second.rounds, entry.second.data}});
    }
    captured.sent = stats.sent;
    captured.seconds = stats.total_time();
    captured.seen = true;
}

namespace {

/// Run the machine the party binary would run. The engine calls the hook above
/// on the way out, so the only difference from `malicious-shamir-party.x` is
/// that the numbers come back structured instead of printed.
template <template <class U> class Share>
QommRun run_honest_majority(int argc, const char** argv,
                            QommChannel* channels, int capacity, int* written) {
    QommRun out{};
    if (written) *written = 0;
    captured = Captured{};
    qomm_after_run_callback() = capture_after_run;
    try {
        ShamirMachineSpec<Share>(argc, argv);
    } catch (std::exception& e) {
        out.ok = 1;
        std::strncpy(out.error, e.what(), sizeof(out.error) - 1);
        return out;
    } catch (...) {
        out.ok = 1;
        std::strncpy(out.error, "unknown failure inside the machine",
                     sizeof(out.error) - 1);
        return out;
    }
    if (!captured.seen) {
        out.ok = 1;
        std::strncpy(out.error,
                     "the engine did not call the hook; is it the patched build?",
                     sizeof(out.error) - 1);
        return out;
    }
    out.rounds = captured.rounds;
    out.raw_rounds = captured.raw_rounds;
    out.sent = captured.sent;
    out.payload = captured.payload;
    out.seconds = captured.seconds;
    int count = 0;
    for (const auto& channel : captured.channels) {
        if (!channels || count >= capacity) break;
        std::strncpy(channels[count].name, channel.first.c_str(),
                     sizeof(channels[count].name) - 1);
        channels[count].rounds = channel.second.first;
        channels[count].bytes = channel.second.second;
        ++count;
    }
    if (written) *written = count;
    return out;
}

}  // namespace

extern "C" {

/// The protocol the paper measures: honest majority, malicious security.
QommRun qomm_run_malicious_shamir(int argc, const char** argv,
                                  QommChannel* channels, int capacity, int* written) {
    return run_honest_majority<MaliciousShamirShare>(argc, argv, channels, capacity, written);
}

/// The same circuit without the malicious-security machinery, which is what the
/// overhead figure is a ratio against.
QommRun qomm_run_semi_honest_shamir(int argc, const char** argv,
                                    QommChannel* channels, int capacity, int* written) {
    return run_honest_majority<ShamirShare>(argc, argv, channels, capacity, written);
}

}  // extern "C"
