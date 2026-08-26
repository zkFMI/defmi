# What a review of this repository found

Two rounds of review, one delegated to a different model and one done here,
against the paper, the three decks and the implementation. Both rounds are
recorded, including what was checked and found sound, because a clean result
is information and a review that reports only failures cannot be read as
coverage.

Every finding below was reproduced before it was acted on. Where the finding
was a soundness claim, reproducing it meant writing the attack and watching it
succeed; where it was a number, recomputing it from the artifact. Two findings
were rejected on that basis and are recorded at the end.

---

## 1. Soundness

### `verify_product` accepted a proof that 2 x 3 = 8

`product_terms` separates its two verification equations with weights `w` and
`w^2`, and its own comment says `w` has to be unpredictable once the proof is
fixed. `verify_product` passed `ONE`. With `w = 1` the two equations are added
before the check, so what is verified is their sum, and a sum of two equations
does not imply either.

The forgery is four lines: choose the two announcements as combinations whose
exponents you know, take the challenge, solve the single aggregate relation for
the three responses. `1 + a` is invertible, which is all a prover needs.

**Reached**: `ValuedCollateral`'s price-times-quantity proof, and the tagged
cash rail's value proof. A pledge of quantity 2 at price 3 could claim a value
of 8 and draw credit against it.

**Fixed** by checking the two equations separately. `verify_same_value` had the
same shape --- sound where the two value generators are independent, since the
sum still separates in their components, and not where they coincide, which is
the untagged case the note rail admits --- and is fixed the same way. The
batched paths were never affected: `Batch::weight` is drawn by the verifier at
verification time, which is the only sound source for such a weight. A
transcript-derived weight would not do: the prover can compute that too.

### A one-out-of-many proof verified against a set it was not made for

The Fiat--Shamir challenge covered the proof's own commitments and not the set
the proof is *about*, and the set entered only through the final weighted sum
`sum_i p_i(x) C_i`. So move mass between two members and leave the sum where it
was --- add `D` to `C_j`, subtract `(p_j/p_k) D` from `C_k` --- and the challenge
does not move either.

**Reached**: the note rail's rings and the asset registry's membership check.
Not the vetting credential, which binds every envelope in its own transcript
before calling.

**Fixed** inside `oneofmany` rather than in each caller. The proof is a
statement about a set, so that is where the set belongs. Proof sizes are
unchanged.

### A published band of [1, 200] accepted 256

The policy audit proves each hidden field lies in the interval the venue
published, and proved something wider. A range proof over `bits` establishes
`0 <= value - low < 2^bits`, and `bits` is the width of the span, so unless the
span is one less than a power of two the interval enforced is the smallest
power-of-two window containing the published one. Every field: `slope` published
0--16 accepted 0--31, `invcoef` 0--8 accepted 0--15, `maxqty` 1--1000 accepted
1--1024.

It leaked nothing --- the hiding is untouched --- but the venue's published
statement that every field is inside its band was false for values in the gap.

**Fixed** by proving both sides. `value - low` and `high - value` are each shown
to be in `[0, 2^bits)`, and their sum is fixed at the span, so together they pin
the interval exactly. It costs a second range proof, against a sixty-second
disclosure interval.

### `--audit-gates` dropped a gate the audit does not prove

The flag stops the circuit paying for facts the registration audit already
established, and it dropped two. The expiry it may drop: the auditor refuses an
audit unless `now < expiry <= now + horizon`. The active flag it may not --- the
audit proves the flag is a *bit* and never that it is set, and could not
usefully prove it is set, because a committed one is a public one and whether a
maker is quoting at all is what committing it hides.

With the flag on, nothing anywhere checked it, and **a maker that had withdrawn
was eligible and could win the tournament**.

**Fixed**: the circuit keeps `active` and drops only the expiry. The measured
45% traffic saving is unaffected --- `rounds.json` records `audit_gates: false`,
so the headline figure was always measured on the sound configuration.

---

## 2. Claims the deployment could not deliver

### The two switches that bind the computation are off by default

A quote proof proves the opened price is the correct function of *the inputs the
nodes used*. Whether those are the shares that were dealt and committed is a
separate question, closed by two mechanisms that catch different parties:
`--shamir-inputs` catches a dealer that deals what it did not commit,
`--input-check` catches a node that passed the share check and then supplied
something else.

Both default to off, and `DEPLOYMENT.md` mentioned neither --- the words "input
check" did not appear in it. Profile B, the audited one, listed the quote proof,
the three times, the interval and the disclosure period, and not these. An
operator following it would publish a proof about inputs nothing had checked.

**Fixed**: section 1.2, with the measured cost (two rounds and 2.03x the
traffic), and a binding row in all three profiles. The defaults stay off in the
harness, because every arm has to be selectable and a default that doubled the
traffic would make the arms incomparable --- which is a property of a research
harness and not an argument for a deployment.

### "About ten probes" was in the paper three times and in no artifact

`DEPLOYMENT.md` tells an operator to set the per-entity cap from the measured
probe count and calls that cap the only defence against reading a maker's
inventory off its own two-sided quotes. The count was not measured anywhere:
the probing attacker had only ever been run at the full budget.

Measured (`artifacts/probe_budget.json`, 24 seeds): the correlation is about
0.53 and **does not grow with the budget**. What grows is the confidence --- from
23% of seeds distinguishable from zero at ten probes, to a majority at 24, to
nearly all at 96. So a cap does not prevent the attack; it sets how often an
entity can refresh its picture. "About ten" was too generous to the attacker.

The first run of that script judged by the size of the correlation and reported
that four probes suffice. That was reading the estimator, not the attack: `|r|`
from four points is inflated, and 0.93 at four against 0.53 at two hundred and
forty is the bias. It judges by significance now.

### The rate limiter's counters do not survive a restart

`EntityRateLimiter` holds three dictionaries in memory. They reset when the
venue restarts and they do not compose across instances, so a venue run as two
processes gives every entity twice its allowance --- for the mechanism the
documents call the only defence. Recorded next to that sentence; persisting and
sharing them is deployment work that has not been done.

---

## 3. Where the record disagreed with the evidence

Eleven figures in the paper and the decks disagreed with the artifacts they
cite. Each was recomputed here before being changed. The largest: matching the
MPC field was priced at 1.6--1.9x rounds, 13x bytes and 1.5--2.2x time;
`matched_field.json` says 1.00x, 2.00x and 1.07x, and carries the superseded
figures in a block explaining why they were wrong. The paper was quoting
neither.

The rest were smaller and of one kind --- a ratio against the wrong denominator,
a term count off by one, a total whose displayed addends do not reach it, a
share of the bytes that was one party's rather than the global one.

Two documents are **generated** from the artifacts and were hand-edited by
mistake, twice: `DEFMI.md` and `AUDIT.md`. A correction written into a build
product is lost at the next build, and in `AUDIT.md`'s case it was --- the file
still said the offline/online split could not be measured, weeks after it had
been. Both corrections now live in the generators.

The input check's cost was quoted against a baseline that does not work: one
round and 0.39% is the cost against the *aggregate* check, which the generator
refuses to emit without `--unsound-check-for-measurement`. Against no check at
all it is two rounds and 0.41%.

---

## 4. Checked and sound

Recorded because a review that lists only failures says nothing about coverage.

- **The circuit does not depend on the request.** The emitted program is
  byte-identical across the market asked about, the size, the direction, whether
  the request is real, a size no maker can fill, and the makers' policies, and
  every node reads the same number of values in all of them. The generator runs
  in the clear, so this is a test and not a reading
  (`rust/qomm-mpc/tests/circuit_is_oblivious.rs`).
- **A slot on the wire is the same whether or not anyone asked.** Same length,
  every share field-uniform, padding random on both arms
  (`rust/qomm-transport/tests/wire.rs`).
- **The registry refuses a substituted rule and accepts a substituted
  parameter**, checked against circuits the generator emits rather than a
  stand-in: the tournament arity, the field width, the number of markets, adding
  a binding limit, adding the input check --- five changes, five refusals.
- **The AUC of 0.500 is earned rather than imposed.** The oblivious arm's
  leakage policy returns nothing because the request never reaches a maker, and
  the paper already says the resulting tie is why the rank statistic degenerates
  and that the plain arm's number is a property of the adversary granted.
- **The six fault types the accountability claim names** --- equivocation,
  omitted makers, stale state, missing receipt, bad signature, forked state ---
  are each emitted and each tested.
- **The demo's seat projection** is looked up server-side from the session, so a
  browser cannot name someone else's seat; and a round whose circuit disagrees
  with the cleartext reference aborts and returns a random masked key, so the
  taker receives no price rather than one nothing vouched for.
- **The trader's mask** is 61 bits against a 20-bit key, so the opened value is
  statistically hiding.
- **No headline figure was measured on a configuration that does not work.**
  One artifact carries an unsound arm, it is named `aggregate_unsound`, and it
  exists to be the comparison.

The reference had one gap of a different kind. Every run is verified against
`gen_qomm`'s cleartext reference, so a bug in the circuit is caught --- but a bug
the two *share* is not, and the test that claimed to be the second opinion was
checking the reference against itself. Its name and docstring said it compared
the reference against the simulator's `MarketMaker.quote`; the body never called
it, and the two could not have been compared anyway, being different
abstractions on purpose. The second opinion is now written from the language's
statement of the rule rather than from the generator, and they agree
(`rust/qomm-mpc/tests/program_parity.rs`).

---

## 4b. A third round, delegated elsewhere

The first delegate's credit ran out partway through the implementation audit,
so the rest went to a different model. It found the most consequential thing in
the review.

### The joint assembly is one opening, and the paper called it the proof

The contribution list said "a publicly verifiable proof that the opened quote
is correct, assembled by a quorum of computing nodes from shares". What is
built and measured is one Pedersen opening: the joint path deals a single
scalar to seven nodes and assembles one sigma proof from a quorum.
`QuoteProver.prove` takes every maker's witness in one call, from one process
holding all of them. The module docstring was careful --- it says the nodes
*can* assemble the proof jointly --- and the paper dropped the "can".

The boundary is worth more than the correction. The product and bit steps do
share the linearity that makes joint assembly work. **The range proofs do
not**: a range proof commits to each bit of the value, extracting bits needs
the value, and a node holding a share cannot do that. Assembling them from
shares is MPC, which is what this construction was chosen to avoid --- and the
range proofs are the dominant cost. The piece that resists joint assembly is
the piece that costs the most.

Corrected everywhere it appeared, and named as an open problem rather than
reported as a measurement.

### Two definitions of `secret_input`, and the second one won

The input check emitted one that recorded each party's share into
`check_store`; Shamir inputs emitted another straight after that applied the
Lagrange coefficients, silently replacing it. Asking for both --- the
arrangement `BINDING.md` recommends, and what the composed arm measured ---
gave a circuit whose check ran over an array nothing had written to. Nothing
failed, because a check over zeros passes.

The measured numbers are unaffected: re-run after the fix, the four arms
reproduce the host-a table to four decimal places, because recording a share
into an array is local. What was wrong was the property and not the price.

### A MAC nothing checked

`frame_mac` was computed on every frame from the first version of the module
and no code anywhere checked one. Thirty-two bytes of every frame carried it,
every traffic measurement counted it, and anyone who could reach a relay's port
could write a well-formed frame into a slot's batch. Verified now, in constant
time, with a count of what was refused.

### A deadline only the node observed

`emitted_at` is a field the node chooses and signs, and lateness was judged
against it --- so a node could miss a deadline, sign `emitted_at = deadline - 1`
afterwards, and be counted as on time. The ledger records when it saw each
receipt and judges by that. And a receipt for another market, with an invented
deadline, counted toward the quorum: both fields are signed and neither was
compared.

### Every site held every node's private key

The two-site runner collected `*.pem` and `*.key` into one directory and
shipped the lot to every machine, so each site could speak as any node. It also
shipped all seven parties' input files everywhere, which any site operator
could add up --- a measurement of geographic independence that handed each site
the secret. Each site now gets the certificates it needs to authenticate the
others, and only its own parties' keys and inputs.

---

## 4c. The settlement layer's ordinary logic

The same delegate then read the settlement layer for logic rather than
cryptography --- state machines, invariants, orderings, the arithmetic between
the proofs. It returned nineteen findings. What follows is what was reproduced
and fixed; the ones still open are at the end, with severity, because a list of
what was fixed is not a statement about what remains.

**A stranger could release somebody else's escrow.** `commit_pending` verified
the release under a key the *caller* handed in and never compared it with
anything, so anyone could sign the leg's name with a key of their own and force
the escrow to settle --- without the adaptor secret, which is what was supposed
to gate it, and while the counterparty's leg unwound. The key is recorded at
prepare time now and the parameter is gone, so the attack is not merely refused
but unexpressible.

**A leg name was spent only while its escrow was live**, so a name could be
reused after commit --- and the release signature covers only the name, so the
first escrow's release settled the second one. Names are spent for the ledger's
lifetime now.

**A batch attestation anyone could compute.** It carried a digest and nothing
else, and `close` compared it against the cycle's own: "attested" meant "the
number matches the number". It carries the quorum's signature now, and a cycle
that asks for attestation must be opened with the key it verifies under.

**A roll a caller could build.** Every field of the vetting `Group` and `Roll`
was public, so a verifier could be handed the thing it was supposed to be
checking against. `Group` is not constructible from outside the crate and
`Roll::digest()` is what a verifier compares against whatever the chain
published.

**A position book could be rebased**, because `open` overwrote --- and the
opening is what conservation is measured against, so the check would pass on any
state. **The mode and the books disagreed**: a cycle labelled gross-gross could
be built from netted books. **The CCP attestation digest** concatenated three
variable-length fields without lengths, so one provider's attestation moved to
another provider and another cycle under the same signature.

**A grant outlived its period by up to a day**, because the remaining time was
rounded up to whole days and multiplied back --- which is exactly the state the
module's own doc calls "current for a scope nothing is being paid into". **Two
authoritative totals wrapped**: the register's position total, which is signed
and reconciled against, and the cross-provider shortfall, which decides how much
capital is called.

**Two documents described behaviour the code does not have.** DEFMI.md said
admission, pledge, overdraft and payment are one event through
`admit_with_credit`, with rollback; that function is in the Python
implementation and not in the Rust port, where `grant` and `admit` are separate
calls and a grant that succeeds before a failing admit leaves the credit
standing. And it said a house could novate trades nobody made and produce a
cycle that checks out --- which stopped being true when both counterparties'
signatures went onto every edge. Omission is what remains.

**The chain's escrow had no payer, no deadline and no unwind**, so an expired
leg still settled to the payee, an unclaimed one was stranded, and this map and
`Ledger` could reach different final states from the same leg. It records both
now, `claim` refuses a late one and `unwind` returns an expired one to the
payer --- the same rule `Ledger::unwind_pending` already followed.

**"Same settlements, same root" was the wrong invariant.** A settlement writes
an absolute commitment rather than a delta, so two that move one account do not
commute. The root is canonical given the *state*, which is what a chain's
ordering is for, and the existing test passed the same moves to both
settlements --- the one case where order cannot matter.

### Open, and ranked

Reproduced or read and not yet fixed. They are listed rather than quietly
carried, because the difference between a review and a list of repairs is
whether it says what is left.

**Nothing is open.** The six that stood here are closed below; what remains is
one thing no code change can fix, recorded under section 7.

---

---

## 5. Findings not accepted

- A review read the 71% figure for a crowd of 32 on Solana off the polynomial
  row alone. It is the total --- polynomial, syscall and transcript --- against
  the 1.4M ceiling, and 987,000/1,400,000 is 70.5%.
- A review reported `verify_same_value` as broken in general. It is broken only
  where the two value generators coincide; where they are independent the sum
  still separates in their components and the value stays pinned. It was fixed
  regardless, because the case that breaks is one the note rail admits.
- A review reported that receipts leak whether a slot did anything, by
  publishing both `prev_state_digest` and `new_state_digest` so that equality
  means no state change. The state is a hash chain --- `H(prev, result)` --- and
  advances every slot whether or not anything happened, so the equality never
  holds and there is nothing to read from it. The finding assumed a state that
  is a snapshot of inventory.

---

## 6. The six that were open, and what each turned out to be

Each was reproduced before it was touched --- an attack written and watched to
succeed, or the arithmetic recomputed --- and each carries the test that fails
without the fix.

### A provider was admitted on a margin nobody checked

`admit` took a `CreditLine` and stored it in a field marked
`#[allow(dead_code)]`. It was never verified, so the backing range proof --- the
entire content of a margin --- was never checked; it was never required to be
under the provider's own handle, so a line built by anybody over anybody's
collateral was accepted; and `has_own_capital` matched any tranche whose *name
contained* the words "provider capital", so the layer that makes an attestation
expensive to get wrong was identified by a string an attacker writes.

The registry then reported the provider as margined, which is the one thing the
entry exists to establish. `admit` now takes the credit context, verifies the
proof, requires the handle to match, and the waterfall names its own tranche by
position rather than by label.

### Two passing children hid a failing parent

The bisection splits a range, asks the register what each half should total, and
checks each half against its commitments. It never checked that the halves add
up to the whole they came from. A register answering with what the ledger
actually holds --- rather than what it attested --- has both halves pass while
the parent still disagrees, and the search returns `found: []`.

That is worse than the pass-or-fail it replaced. Pass-or-fail says there is a
break; this said the break was nowhere.

### An attestation that fit any cycle ending the same way

`batch_digest` covered the mode, both books' closing snapshots and the admitted
count. Nothing in it said *which* cycle. Two cycles that close in the same state
--- a quiet day, the book carried forward, nothing admitted --- produced the same
digest, so the quorum's signature over one settled the other. A `Cycle` now
carries an identity, it is length-prefixed into the digest, and an empty one is
refused at construction.

### A file that lost rows read as a smaller holding

The parser already refused a row truncated *inside* a row. A file truncated at a
row boundary --- the likelier case, since files are written a line at a time ---
was a well-formed statement of less stock, and reconciliation reported a break
against a ledger that was correct.

No content can distinguish it, so the format now ends with a line saying how
many rows there were and what they came to. Truncation takes that line with it.
It does not defend against an edited file; that is what the register's signature
is for.

### Headroom computed in a width its inputs do not fit

A position is `i64` and an amount is `u64`; their difference is neither. Past
`2^63` the cast made the amount negative, so subtracting it *added* to the
headroom. An order of `2^63 + 100` against a zero position and no cap proved
itself covered --- and the old expression stayed inside `i64` while doing it, so
no overflow check would have caught it. Now `i128`, and bounded by the width of
the proof that carries it.

### A schedule that never rolls

`Rolling { period: 0 }` was constructible and `period_of` divided by it. The
panic is the smaller half: zero has no honest answer, because every instant
falls in one scope, and a permanent scope is what the rolling schedule exists to
replace. The field is private and the constructor refuses it.

---

## 7. The empirical side, which nobody had audited

The cryptography and the implementation had each been through three rounds. The
negative results --- the disclosure's own harm, the timings, the staleness
analysis, the real-data arms, the seeds --- had been through none. That is the
half where an error flatters the design, because nobody goes looking.

### The fill count was under-noised by a factor that grows with the market

The disclosure claims add/remove-one-entity adjacency and calibrates each
field's noise to one entity's cap. Three of the four fields are built from
per-entity maps and clipped per entity, so they honour it. The fill count was a
bare total, clipped against the *request* sum:

```
clipped_fills = min(total_fills, sum_e min(requests_e, R))
```

Remove one entity and that moves by up to `n * R`, not `R`. The window where it
bites is an ordinary one: a single maker takes the flow while the others only
ask. With eight entities and `R = 3` the released count moved by 24 while
carrying noise calibrated to 3.

**The audit could not have caught it, because the audit was testing the wrong
neighbour.** `_drop_entity` removed the entity from the three per-entity maps
and copied `fills` across unchanged --- so in the two worlds it compared, the
fill count was identical by construction and the only field with a broken
sensitivity was the only field it could not see. That is the defect that hid the
defect.

Fills are now recorded per entity, clipped per entity, and the audit's neighbour
removes the entity from every field.

### Whether a window published at all was a report on the private data

The mechanism charged the entities *active* in the window and withheld the whole
release if one of those was out of budget. So take an entity that spent its
budget earlier: the window is withheld exactly when it trades and published when
it does not. Two neighbouring worlds, probabilities one and zero. No finite
epsilon covers a bit like that, and it is a bit published every window.

Every enrolled entity is now charged every window, active or not. The schedule
is then a function of the enrolment and the window count, both public. The price
is real and is now stated: enrolment buys a fixed number of windows, and sitting
one out does not save it.

### The signal-to-noise ceiling was computed over 2,400 windows at once

The paper put `N = 2{,}526` --- every distinct address in the UniswapX tape ---
into `SNR = 0.6745 \varepsilon_{field} \sqrt N` and got 8.47, which reads as
"a real venue has more than enough firms". The noise is drawn **per window**, so
`N` is the firms contributing to *one* window. Those 2,526 addresses are spread
over 2,400 windows.

| N | basis | ceiling |
|---|---|---|
| 2,526 | every address, all windows pooled (what was reported) | 8.47 |
| 11 | distinct swappers per 150-block window, raw tape median | 0.56 |
| 1.87 | requests per window in the run itself (4,485/2,400) | 0.23 |

**The corrected reading reverses the conclusion.** SNR = 1 needs 35.2 firms in
the same window, and the busiest basis the real tape supports gives 0.56. The
negative result is stronger than the paper claimed, not weaker.

### The staleness sample is conditioned on the outcome

Every observation is a *fill*. An order that did not settle leaves no `Fill` log
on Ethereum, and a quote that went stale is exactly the kind that does not
settle. The sample is selected on something downstream of the thing being
measured, and the direction is not neutral: drift large enough to stop a trade
is missing from the drift estimate.

Nothing in this dataset removes it --- only a feed of unfilled orders would. So
the figure is now stated as a lower bound, and the direction of the bias is
stated with it.

**The gap was 24 s, not 26.** Two Ethereum blocks at 12 s. The artifact's own
key said `median_ratio_at_26s` and the paper said 26 throughout; the number
measured was always the two-block one.

**The post-hoc choice of four pairs turned out not to matter,** which is worth
saying because it was a fair thing to suspect. Sweeping it: 2 pairs 1.01, 4 pairs
1.01, 8 pairs 1.01, 16 pairs 0.90, 32 pairs 1.03.

### Intervals were normal where the sample was small

Three scripts multiplied the standard error by 1.96 at every `n`. At the eight
seeds the disclosure-harm arms ran, the multiplier the sample earns is 2.365; at
the five seeds a per-symbol cell runs, 2.776. The quantile is now derived from
the incomplete beta now in `rust/qomm-measure/src/beta.rs`, checked against the published table
at eight degrees of freedom (12.706, 4.303, 2.776, 2.365, 2.179, 2.086, 2.064,
1.980 --- all agreeing to four places).

### The pre-registration said five repetitions and three were run

`THEORY.md` fixed five repetitions or more in advance. `rust/qomm-harness/src/bin/run_three_times.rs`
defaulted to
`--slots 3` and nobody passed the flag, so three is what the artifact holds. The
deviation came from a default that disagreed with the plan rather than from a
decision, so the default is now five.

### Two of the three exported repositories had test suites that could not run

The export check verified that every declared test *file* was present. It never
checked that any of them collected. Both the qomm and defmi exports shipped
tests importing `zk`, which neither export carried, so four tests in one and two
in the other failed at import --- and the check printed "exports agree on the
shared modules and carry what they declare" the whole time.

The exporter now creates a minimal `qomm-harness` for each repository, generates
that repository's actual Cargo workspace, and runs `cargo test --locked --workspace`
from an isolated copy of each exported
tree. This catches missing Rust source, missing crate or bin dependencies,
non-compiling generated manifests, and failing unit or integration tests; the
former collection-only check could see none of those Rust failures.

This one was not found by reading the code. It was found by running the thing
the check claimed was fine, which is the only way this class of defect surfaces.

### What the four-field audit says now

Extending the two-world game from the request count to all four released fields
puts every one of them inside its claim across 288 cells. The fill count --- the
field nothing had ever audited --- is the tightest of the four, at 89.9% of its
claim at the audited budget against the signed volume's 74.8%. The field most
worth measuring was the one not being measured.

The audit is not passing vacuously. On the window that broke it --- one entity
taking the flow, seven asking --- the corrected clipping measures 0.168 against a
per-field claim of 0.25, and the old clipping measures 1.761: seven times the
claim, on the same window, in the same game. Both halves are a test, so neither
can rot.

---

## 8. The open problem, priced

The joint-assembly boundary in section 4b was recorded and left there: the range
proofs cannot be assembled from shares, they dominate the cost, and that is an
open problem. An open problem with no number attached is one nobody can size,
and "we did not build it" reads the same whether the reason is a week of work or
a decade of it.

**What actually blocks it is narrower than it looked.** Everything downstream of
*having shares of the bits* is already solved here. A Pedersen commitment is
linear in the exponent, so `C = g^b h^r` is the product of one term per node and
each node computes its own; the bit proofs and the tie-back are sigma protocols,
whose responses are linear in the witness, and `threshold_sigma` already
assembles those --- measured at 1.83 ms for a quorum of three, with
`no_node_holds_witness` confirmed. The single missing piece is shares of the
bits.

**And the circuit already computes them.** Its `fits` and `fresh` gates compare
`maxqty - qty` and `expiry - now`, which are exactly the differences the range
proofs are about, and a prime-field comparison decomposes internally. So the
question is not what a bit decomposition costs standing alone. It is what it
costs on top of a comparison already being paid for.

Measured on host-a, seven parties, malicious Shamir at `T=2`, `-F 128`, with the
same runtime counter that gives the circuit its round count:

| values | comparison alone | comparison + bits | marginal |
|---|---|---|---|
| 48 at 13 bits | 35 rounds | 49 | +14 rounds |
| 48 at 26 bits | 35 rounds | 50 | **+15 rounds, +5.3 MB** |
| 48 at 52 bits | 35 rounds | 57 | +22 rounds |

Forty-eight is sixteen makers times the three range proofs each needs. Rounds are
flat in the number of values --- 26 at N=1 and 26 at N=48 for the standalone
decomposition --- so parallelising across makers costs no depth. Width is
log-depth rather than one round per bit: 5, 6 and 7 extra rounds at 13, 26 and 52.

At the per-round cost the three-times run measures, +15 rounds is 215 ms on a
metro committee and 932 ms across regions: **9.5% and 17.6% of the slot**. What
it buys is that no node ever holds every maker's witness.

### Two predictions written before the measurement, and how they did

Recorded here because a prediction that is only reported when it was right is
not a prediction.

- *"Bit decomposition costs ten rounds or fewer, from a log-depth adder."*
  **Wrong.** It is 26 rounds standalone. The depth-driven part is small --- one
  extra round per doubling of width --- but there is a fixed cost of about 24
  rounds on top of it, which the log-depth argument did not account for.
- *"N in parallel costs the same as one."* **Right**, and it is the load-bearing
  half: it is why 48 range proofs cost +15 rounds rather than 48 times anything.
- A third reading, that 26 rounds at 26 bits meant one round per bit, was a
  coincidence and the width sweep killed it. Worth recording because it was
  briefly convincing and would have made the wide-area figure much worse.

---

## 9. The open problem, built

Section 8 priced the missing piece. This is the piece.

### One step really could not be shared, and it was not the one expected

`prove_bit` is a Chaum--Pedersen disjunction. The prover proves the real branch
and simulates the other, and it picks which is which *from the bit*:

```python
real, fake = bit, 1 - bit
t0, t1 = (t_real, t_fake) if bit == 0 else (t_fake, t_real)
```

A node holding a share cannot make that choice. This is not a hard case of
interpolation --- there is nothing to interpolate. The decision is control flow,
and control flow is not a field element.

### What replaces it, and why it is the same statement

Over a prime field `b in {0,1}` is exactly `b*b = b`, which is a multiplication,
and `prove_product` proves multiplications with responses that are linear in the
witness: `z_b = k_b + c*b`, `z_rb = k_rb + c*r`, `z_s = k_s + c*s`. Both
first-move points are a node's own share in an exponent over a public point, so
both interpolate in the exponent. Setting all three commitments of the product
proof to the same `C_j` proves `b^2 = b` about the value inside it.

Reading the verifier's two equations with `c_a = c_b = c_c = C = g^B h^p`: the
first pins `(b, r)` opening `C`, so `b = B` by binding; the second forces
`C = C^b h^s`, hence `B = B*b` and therefore `B(1-B) = 0`. In a field that is
`B in {0,1}`.

### What was built

`rust/qomm-proofs/src/threshold_range.rs`, with `deal_bits` modelling what an MPC decomposition
hands over --- shares of each bit, its blinding, and the cross term
`s = r(1-b)`, which is one multiplication. Nothing in the assembly path ever
sees a bit.

The test that matters is not that it verifies. It is that **a commitment holding
2 is refused**: a square proof that accepted 2 would make every range proof in
this work decorative, so that test is the construction's whole foundation. Also
tested: a proof does not verify against another commitment, the context is
bound, a node answering on a tampered share breaks the proof, `T` shares are not
a quorum while any `T+1` are, and no party's share equals the value or any bit.

### What it costs, on host-a

| bits | per node | local prover | ratio | assembled | local | ratio |
|---|---|---|---|---|---|---|
| 8 | 3.9 ms | 3.5 ms | 1.11x | 1,632 B | 1,888 B | 0.864x |
| 26 | 12.2 ms | 11.1 ms | **1.10x** | **5,088 B** | 5,920 B | **0.859x** |
| 32 | 15.0 ms | 13.7 ms | 1.09x | 6,240 B | 7,264 B | 0.859x |

Per node is what a node waits for. Quorum total is 3.29x, which is the same work
divided three ways rather than extra work --- and it is the number that would be
misleading if quoted alone.

**The prediction written in section 8 was that per-node work would equal
single-machine work, because a Pedersen commitment is one term per node.
Measured: 1.09--1.11x.** The residue is the Lagrange combining, which the
argument did not count.

**The proof came out smaller, which was not predicted at all.** A square proof
carries three scalars per bit where a disjunction carries four, so the
substitution forced by the threshold setting happens to save 832 bytes at 26
bits. Recorded because it was luck, not design.

### What is not done

The quote prover still calls the local `prove_range`. What exists is the
primitive and its measurement, not the integration: assembling the *whole* quote
proof jointly needs shares of every witness, not only the range proof values.
The claim that changed is feasibility, and only that.

---

## 10. The claim as written

Section 9 built the range proof. This wires it into the quote proof, which is
what the range proof was blocking. It does not by itself make the contribution
sentence true --- see section 12, where an independent review found the verifier
was not binding the policy to the published key at all, so a proof that
assembled correctly was a proof of a weaker statement than the sentence claims.

### What one process used to see

`QuoteProver.prove` takes every maker's witness in one call. That process holds
every pricing rule in the market at once: whoever runs it, or gets into it, has
the thing seven nodes exist to keep split. The proof it produced was correct.
The property claimed around it was not.

### What each step needed

Every step of the statement is one of four shapes, and only one of them was in
doubt:

| shape | steps | assembles? |
|---|---|---|
| linear combination | `ask`, `bid`, `cost`, `key` | free --- Pedersen is linear in both exponents |
| product | `depth`, `skew`, the two conjunctions, the cost gate | yes --- responses are `nonce + c*witness` |
| bit | `active`, and the bit inside each gate | **no**, as a disjunction; yes as `b*b = b` |
| range | `fits`, `fresh`, minimality | via the bits |

`Shared` carries the linear parts: shares add, subtract and scale, and the
commitment moves with them. Adding a public constant works because the Lagrange
coefficients at zero sum to one. Products cannot be carried that way --- a
product of two degree-`t` sharings has degree `2t` --- so they come from the
multiplication protocol, which is what the circuit already runs, and the proof
machinery only has to show that what it emitted is right.

### What it cost, on host-a

| makers | per node | local prover | ratio | verify assembled | verify local | ratio |
|---|---|---|---|---|---|---|
| 2 | 81.5 ms | 77.0 ms | 1.06x | | | 1.18x |
| 4 | 162.9 ms | 154.0 ms | 1.06x | | | 1.18x |
| 8 | 326.1 ms | 308.5 ms | 1.06x | | | 1.18x |
| 16 | 653.0 ms | 617.5 ms | **1.06x** | 821.8 ms | 697.6 ms | **1.18x** |

Flat in the number of makers, which is the shape the argument predicted: a node
does the same work the single prover did, not extra work, because a commitment
is one term per node. Plus the 15 rounds for the bit shares.

### Two mistakes worth keeping

**The product proof's second factor.** `_joint_gate` passed the product where
the *value* belonged. It typechecks, it assembles, and it proves a different
statement --- the verifier caught it, which is the only reason it is a note here
rather than a defect. The comment in the code says so at the call site.

**A mismatched proof crashed the verifier instead of refusing it.** Handing an
assembled proof to the ordinary verifier raised `AttributeError` out of
`verify_product`, because the leaf checkers assumed the shape of what they were
given. "Does not verify" and "kills the process" are different outcomes and a
caller has to be able to tell them apart, so the leaf verifiers now type-check
and return `False`. Found by writing the test that the two flavours refuse each
other --- which was written to pin the substitution, not to find this.

### What the verifier does about the substitution

One switch, not a second verifier. `QuoteVerifier(assembled=True)` swaps the two
leaf checks; everything above the leaves is the same code. A copy of that logic
is where the next defect would live, and the two flavours are tested to refuse
each other's proofs rather than to accept them quietly.

### What is still modelled

`deal_quote_shares` stands in for the circuit: it evaluates every wire and
shares it. That is the shape of a real handover, and the *proof* steps read
shares --- but `joint_prove_quote` also takes the `MakerWitness` list, and
`registered()` reads the policy in the clear to build the public statement, so
"reads shares and nothing else" is not true of the function as a whole. One
process also holds every party's shares, which a deployment would not. What is established is that the proof
assembles and what it costs; what is not is the plumbing to the running circuit.

---

## 11. The shares are the circuit's own

Section 10 assembled the whole proof from shares a dealer produced. This makes
*some* of them the shares the circuit computed on, and it is worth being exact
about which: the harness proves a product and three bits over the circuit's own
wires, and does not assemble a full `QuoteProof` from them. The wires the full
proof needs and the circuit does not persist are listed at the end.

### What the gap was

`gen_qomm` wrote `sint.write_to_file([best_key])` --- one value --- and its own
comment said why: "until now those shares were supplied to the prover separately
from the ones the circuit computed on, so nothing said they were the same
numbers". `test_share_binding` closed that for the winner. The proof is made of
sixty other wires.

### What was built

The circuit now parks every wire it computes --- `mid`, `half`, `slope`,
`invcoef`, `inv`, `maxqty`, `expiry`, `active`, `depth`, `skew`, `ask`, `bid`,
`fits`, `ok`, `key` --- in arrays the write site can reach, and writes each
node's share of all of them under `--persist-wires`. `persistence.read_wires`
reads them back as share maps and reconstructs nothing, because reconstructing
is the thing the arrangement exists to avoid.

### The run, on host-a

Seven parties, malicious Shamir at `T=2`, four makers, `--shamir-inputs`:

- the field is **253 bits and equals the ed25519 scalar order**, which is why
  that option exists --- shares in another modulus are not witnesses for these
  proofs, they are numbers that resemble them
- the winner reconstructs to 400,118 = 100,029x4 + 2, the pair the circuit opened
- **every one of the 35 quorums agrees on every one of the 60 wires**
- every commitment is computed *from* the shares, and agrees with the direct one
- `depth = slope * qty` is proved on the circuit's own slope and depth shares
- `fits`, `ok` and `active` are proved to be bits by the square proof

### Three things this run found

**The persistence header's prime width was hard-coded at sixteen bytes.** Right
for the default field and silently wrong for any other. Over the matched field
the element is 32 bytes and reading 16 returns `2**124` --- not the prime, not
prime, and not invertible, so the Montgomery step raised rather than returning a
wrong answer. That was luck: a modulus that happened to be invertible would have
produced shares that reconstruct to nothing in particular and a proof about
them.

**MP-SPDZ appends to the persistence file.** A directory run three times holds
three blocks, newest last, and reading from the front returns the first run.
That answer still reconstructs, still agrees across quorums, and still assembles
into a proof --- about a request nobody made. The reader takes the trailing block
and says how many it found.

**A control that did not apply.** Proving `depth` against a quantity the circuit
did not use is refused --- for two of the four makers. The other two have
`slope = 0`, where `depth = slope * anything` is *true*, both sides being zero,
and the proof is right to accept it. Reporting four passes would have been the
lie; the artifact now records which makers the control bites on and carries a
second control --- the same proof against another maker's depth --- that bites on
all four.

### What is still outside

The full assembly is not yet driven from the persisted wires. The circuit keeps
`fits` as the *bit* `qty <= maxqty` while the proof's gate wants the signed
margin `maxqty - qty`, and it does not persist `qty`, `fresh`, `both`, `gated`,
the minimality decompositions, the bit blindings or the cross terms.
`shares_from_circuit` exists and nothing calls it. What the run demonstrates is
the join --- commitments from circuit shares, one product and three bits proved
on them --- not the whole proof driven end to end.

Blindings and cross terms do not come from the circuit and should not. A
Pedersen blinding is not something the computation knows about; a cross term
`r_c - r_a*b` is one multiplication, which the protocol already runs. The
harness supplies both, and the one place it reconstructs anything is there,
marked in the script as the boundary.

---

## 12. What the review found, and it was not in the new code

The threshold assembly of sections 9 to 11 went out for review. The construction
survived; the thing it was assembling did not.

### The verifier never joined the policy to the price

`QuoteVerifier` checked every piece --- depth is slope times quantity, skew is
invcoef times inventory, eligibility is the conjunction of three tests, the
gated cost is the cost gated by eligibility --- and never checked that the
**cost** was those pieces, or that the **key** was that cost. The chain from the
registered policy to the published number had a gap in the middle, and the
minimum was taken over numbers that entered from the side.

Three demonstrations, all run:

| | before | after |
|---|---|---|
| replace a maker's `cost` commitment outright | accepted | refused |
| delete every minimality proof | accepted | refused |
| winner index `-3`, which Python reads backwards | accepted | refused |
| winner index `99` | `IndexError` | refused |
| a proof about no makers | accepted | refused |
| **a buy proof republished as a sell** | **accepted** | refused |

The last is the one that matters. Two makers whose order reverses between
buying and selling: the buy proof, published with `direction = 1`, verified and
named maker 1 when maker 0 wins selling. **`main.tex` said "a wrong winner is
not provable", and a wrong winner was provable** --- by changing one public
field and nothing else.

The fix is not a new proof. Everything missing is linear, so it is an equality
on commitments the verifier already holds: `ask` and `bid` are rebuilt from
`mid`, `half`, `depth` and `skew`; `cost` is one of them by the public
direction; `shifted_cost` is `cost` less the sentinel; and the key commitment is
`gated` raised to `n_slots` and shifted by `sentinel * n_slots + i`.

**This defect predates the threshold work by the whole project.** It was found
because assembling the proof from shares required reading what the verifier
actually checks, line by line, and the reviewer read it without assuming the
pieces added up to the statement.

### The persistence header was read from the wrong field

The 4-byte length after `"Shamir gfp"` is the prime's minimal byte length, from
`octetStream::store(bigint)`. It was being read as the *element* width. Those
agree at 128 and 253 bits --- 16 and 32 bytes --- and diverge as soon as the
prime is not a whole number of limbs: a 100-bit prime declares 13 and the body
strides 16.

And the Montgomery flag, which `Zp_Data::pack` writes right after the prime, was
not read: every value was divided by R whether or not it was in Montgomery form.
The reviewer demonstrated the consequence and it is the sharp one --- with the
flag misread, **all 35 quorums still agreed**, on a number that was not 400,118.

**So "every quorum agrees on every wire" is not evidence that the parse is
right.** It was quoted as if it were. Agreement tests the sharing; only the
header tests the reading. Both are now read from MP-SPDZ's own writers, the
element width is derived from the limb count, and a share that is not reduced
modulo the prime is refused rather than silently reduced.

### The joint nonce note was wrong in a way that mattered

It said a node could only choose the nonce if it spoke last *and everyone else
was corrupt*. The second half is false: speaking last and seeing the others is
enough --- contribute `t - K` and the nonce is `t`, and a known nonce gives up
the witness through `z = k + c*w`. Honest contributions that are already public
protect nothing. What is needed is that one honest contribution is still unknown
when a node fixes its own, which is private dealing or commit-then-open, and the
class models the output of such a protocol rather than being one.

### Attribution does not extend to the new proofs

`audit_partials` names the node whose partial does not match its published
share. `joint_prove_opening` calls it. The product, range and quote assemblies
return no partial transcript and no coefficient ladder, so a bad partial breaks
the proof and cannot be attributed --- and `public["assembled_by"]` is not bound
to anything, so it can be changed after the fact. Recorded rather than fixed.

### What the review checked and found sound

- The `b*b = b` substitution, with the derivation written out: the first
  equation pins `(b, r)` opening `C`, so `b = B` by binding; the second forces
  `C = C^b h^s`, hence `B = B*b` and `B(1-B) = 0`. Sound, and the reviewer was
  right to add that the second step uses *computational* binding again and that
  extraction is knowledge-soundness in the random-oracle model, not group
  algebra. With `log_g h` known, a commitment to 2 passes --- as it must.
- Honest-verifier zero knowledge of the square proof, with the simulator
  written out. It hides the bit as well as the disjunction does.
- The `r(1-b)` cross share: one or two of them reveal nothing; three reveal the
  bit, but three shares already reconstruct the bit itself, so it is not a leak
  across the threshold.
- Lagrange coefficients, scalar and exponent combination, `Shared` arithmetic,
  `commitment_from_shares`, every cross-term formula, the range linkage and bit
  weighting, and that three shares assemble where two do not.

---

## 13. The four that were left, and one the work found on its way

Section 12 fixed what the review found. This is items 1 and 3 to 5 of the list
that stood after it, and a fifth thing that only appeared once the wires were
actually joined.

### The reference price was in the circuit and not in the proof

Driving the assembly from the circuit's own shares meant checking that each
linear wire the verifier rebuilds equals the one the circuit computed. `ask`
did not. The circuit prices as

```
anchored = mid + use_ref * ref
ask      = anchored + half + depth + skew
```

and the quote proof's statement is `ask = mid + half + depth + skew`. **The
proof was about a simpler rule than the circuit runs.** The proof carries eight
registered fields; the circuit has ten, and the two it does not carry are
`asset` and `use_ref`.

**No amount of reading either side alone finds this.** It appeared the moment
the two were made to agree on a number.

The fix is not to teach the proof about the reference. It is that the reference
does not belong in the price rule. A maker here holds no standing registration
--- its policy is a secret input it re-deals whenever it likes, measured at 39.6
full policy changes a second and 352 single-field ones, against a quote that
takes 2.25 s. So the reason an anchor exists elsewhere, that a committed price
goes stale as the market moves, does not apply: a maker prices on its own
account and withdraws by setting one field. `--reference none` removes the term,
and with it a `REF_TABLE` that was a compile-time literal, so every quote was as
old as the compilation.

With the reference gone the circuit and the proof compute the same rule, and the
whole quote proof assembles from the circuit's own shares:

```
circuit self-check : got=(29, 2) want=(29, 2)   verified
assembled from the circuit's shares : verifies
winner 2, value 118   |   circuit opened 118
```

### A multiplication re-randomises, so equal values are not equal shares

The first version of that check compared share by share and failed on wires that
agreed. The circuit reaches `ask` through `anchored = mid + use_ref * ref`, and
even at `use_ref = 0` that product is a *fresh* sharing of zero --- the shares
differ, the value does not. The check compares values. A deployment does not
reconstruct to do it: `C_circuit / C_derived` being a power of `h` is an opening
of zero and assembles like anything else.

### Attribution now reaches the product assembly

`audit_partials` named a bad partial for the opening assembly only, which is one
proof out of the dozens in a quote. `joint_prove_product` takes an optional
transcript and `audit_product_partials` reads it: a node's contribution has to
satisfy both verification equations against the commitments to *its own* shares,
so a verifier names the culprit without holding a share. Tested at both
boundaries --- the bad node is named, an honest quorum names nobody --- because a
check that names everybody is as useless as one that names nobody.

### The joint nonce is a protocol now, not a sum

`CommittedContributions` seals every contribution before any is opened. A node
that waits for the others has nothing to wait for, and one that opens to
something other than what it sealed is caught. This is what the corrected note
in section 12 said was needed; now it is code.

### The assembly runs across processes

The 1.06x per-node figure was arithmetic --- total work divided by the quorum ---
from one process that held every share and could have reconstructed every
witness. `rust/qomm-harness/src/bin/run_distributed_assembly.rs` runs one OS process per node, each handed
**one share of each value and nothing of anyone else's**, asserted rather than
described. On host-a: 8.7 ms wall, 3.4 ms of it a node actually waiting, 288
bytes between them, and the proof verifies.

---

## 14. The disclosure question had an answer nobody had asked for

The query mechanism of section 13 was built to replace the published sums. Then
it was measured, and the measurement went somewhere else.

### The instrument first

`rust/qomm-sim/src/market.rs` states the channel the whole disclosure design rests on:

> The premium is proportional to the maker's *estimate* of the informed
> fraction. A better estimate is worth money, which is the channel through which
> public market information can improve market-maker profitability.

So the question is whether any statistic tracks the informed fraction. Two do
not:

| statistic | median &#124;correlation&#124; with the window's true phi, 5 seeds |
|---|---|
| firms quoting inside a band | 0.094 |
| mean winning half spread | 0.069 |

Both straddle zero across seeds. And the band count, which is what a range query
returns, takes two values --- 6 or 7 of 16 --- while the true phi moves from 0.283
to 0.605. **The sensitivity-1 query is a 300x better instrument pointed at
nothing.** Noise was never what stopped it.

### Then the ceiling, and the overclaim it produced

Rather than search for a statistic that tracks it, hand the maker the true
figure. Over 12 seeds against no disclosure, with Student intervals, every maker
informed:

| | everyone informed | one maker informed |
|---|---|---|
| fill rate | **+0.07 ± 0.02** | +0.02 ± 0.02 |
| PnL per fill | **−334 ± 115** | −83 ± 88 |
| PnL total | **−2,068,127 ± 767,716** | −475,004 ± 516,304 |
| that maker's own PnL | −154,522 ± 196,353 | **−155,171 ± 243,588** |
| taker's cost | **−7.3 ± 2.4 ticks** | **−1.8 ± 1.7 ticks** |

**The first version of this section said "the ceiling is negative, so no
mechanism reaches a positive." That was wrong and a reader caught it.** The
maker here does not choose how to use the figure: `BeliefState.combined`
substitutes it by precision weighting, and an exact signal outweighs the maker's
own estimate entirely. So the arm measures *naive substitution of the
market-wide figure for the maker's own conditional estimate*, not the value of
the information. A maker free to ignore it cannot be worse off for having it ---
that is a theorem, and no measurement overturns it.

Splitting the arms is what the correction needed. Giving the figure to **one**
maker isolates whatever private value it has from the competition effect of
everyone narrowing at once, and there **nothing is detectable**: −155,171 ±
243,588, crossing zero. The collective loss is real and the private effect is
not measurable.

So what is supported is narrower and still worth having: **the prescribed use of
this statistic is not profitable** --- individually indistinguishable from
nothing, collectively a loss, and a gain to the taker either way. What the same
information is worth *used well* is unmeasured, because nothing here optimises
over uses.

The winner's curse is a plausible mechanism for the sign and is recorded as
that. A maker's estimate is formed on the flow it filled, and it fills by
winning an auction, so that flow is more informed than the market's average;
the market-wide figure is the wrong conditioning.

### What was predicted, and what happened

Written before the run: "the query arm is no worse than no disclosure on fill
rate, and better on PnL --- and if not, the mechanism is right and the use is
wrong." The second half is what happened.

And then a second prediction, made in the writing rather than before it, was
wrong: that the ceiling being negative meant no mechanism could reach a
positive. It does not follow, because the arm forces a use rather than offering
one. Recorded because it is the same error this review has found repeatedly in
other people's work --- a measurement of one thing reported as a measurement of
a larger thing --- made here while writing up a review about exactly that.

## 15. A reader asked whether quotes are published, and nine claims did not survive it

The question was one sentence: the venue does not publish quotes, does it. It
does not, and following that through found a conflation in a passage written
minutes earlier, which in turn opened an audit that a second model (gpt-5.6-sol
at maximum effort) was asked to widen. Nine findings. **Three are mine from this
session, one of them in material committed an hour before.** Every one below was
re-verified here against the artifacts rather than relayed.

### The error class, stated once

A comparative claim is made --- *works equally in both*, *unchanged in every
regime*, *predicts the real market's success* --- and only one side of the
comparison was actually computed, or the two sides were computed by different
estimators against different targets. The number that gets quoted is the one
that was measured; the comparison is supplied by the sentence. This is the same
shape as the fill-count sensitivity break of section 6 and the "ceiling is
negative" overclaim of section 14, and it is now the third time it has been the
finding.

### 1. Two probing attacks are reported as one (mine, and pre-existing)

`main.tex:1206` says recovering aggregate maker inventory from firm two-sided
prices "works equally in both, because the midpoint of a two-sided quote cancels
the half spread". `main.tex:1219` and `main.tex:2546`, added this session,
elaborate the mechanism: a quote *is* `m + skew ± half`, the midpoint is
`m + skew` whatever the half spread, so the answer carries the maker's
inventory.

`rust/qomm-sim/src/attackers.rs` computes **two** correlations, not one:

| estimator | input | target | populated in |
|---|---|---|---|
| `net_inventory_corr_from_best_quote` | `best_ask`, `best_bid` | **aggregate** net inventory | every arm |
| `own_inventory_corr_from_per_mm_quotes` | each maker's own two sides | **that maker's** inventory | `plain_*` only |

Splitting `sim_matrix*.json` by the `protocol` field:

| market | aggregate (all six arms) | per maker (plain only) |
|---|---|---|
| generated | 0.5054 | 0.9848 |
| Bybit | 0.1669 | 0.9630 |
| UniswapX | 0.0641 | 0.9925 |

The aggregate figure is identical across all six arms to four decimal places, so
"works equally in both" is exactly right **about the aggregate attack**. The
cancellation argument describes the **per-maker** attack, where the half spread
does cancel and the correlation is 0.96--0.99 --- and that attack has no input
at all against this design, because `best_ask` and `best_bid` come from
different makers and per-maker quotes are never published (`rust/qomm-sim/src/engine.rs`, "only
leaked by plain protocols").

Two consequences. The mechanism as written **cannot produce the measured
magnitude**: a clean cancellation gives a correlation near one, not 0.064. And
the design's strongest privacy result on this attack --- it removes per-maker
inventory recovery entirely --- **is in the artifacts and in no sentence of the
paper**. Writing it correctly makes the result better, not worse.

`probe_budget.json` inherits the confusion: its `attack` field says "own
two-sided quotes" while `rust/qomm-harness/src/bin/run_probe_budget.rs` runs QOMM and reads the
aggregate estimator. The 24 and 96 probe figures, and the shipped cap of 60,
are calibrated on the **generated** market, where the aggregate attack is 3x
stronger than on Bybit and 8x stronger than on UniswapX. The cap is therefore
conservative, which is the safe direction, and the paper does not say so.

### 2. The firm-count explanation is inverted (pre-existing, most severe)

`main.tex:1354` says what was unusual about the generated market was that it had
too few firms; `main.tex:2568` says this "places the generated market's failure
in its firm count ... and predicts the real market's success before measuring
it."

`snr_model.json`:

| | firms | SNR ceiling |
|---|---:|---:|
| generated market | **24** | **0.826** |
| real tape, distinct firms per window | **11** | **0.559** |
| real tape, requests per window in the run | 1.87 | 0.231 |

SNR 1 needs 35.2 firms per window. The real market has **fewer** firms and a
**lower** ceiling than the generated one. Firm count does not predict the real
market's success; on this model it predicts the real market should do *worse*.
The paper's own SNR passage at `main.tex:1344` already contains the numbers that
contradict the story built on top of them.

This is the one finding that cannot be closed by rewording. Either the causal
claim is withdrawn and the real market's better behaviour is left unexplained,
or a different variable is found, which needs measurement that does not exist.

### 3. "The settled count is public" rests on an unmeasured premise (mine)

`main.tex:2224` and `main.tex:2587`, both written this session, say settlement is
one on-chain instruction per trade "at 18,197,763 to 65,694,220 gas, so anyone
with a node counts them exactly".

`evm_settlement.json` labels those figures itself: **"an equivalent count, from
settle time over one scalar multiplication on the same machine. A floor."** They
are a projection from off-chain timing, not a measurement of a transaction. The
paper says elsewhere that the verifier is not deployable on chain
(`main.tex:1956`) and that the measured settlement is in-process.

The premise is not baseless --- `rust/qomm-sim/src/engine.rs` states the simulator's leakage
model as "in every arm a settled trade is visible on chain (wallet, size,
time)", and the stated adversary sees what the settlement layer publishes --- but
it is a **design assumption**, not a result, and it was cited as a measurement.
Worse, `block_range_query.json` declines to measure the fill count *because of*
this assumption, so the assumption justifies the absence of the measurement that
would test it. That is circular and is now recorded as such.

### 4. The settlement leakage model and the zkPI design disagree (found here)

Not on either list; it follows from 3 and 5 together. `rust/qomm-sim/src/engine.rs` grants the
observer wallet, size and time on every settled trade. The zkPI of section 12
hides asset, quantity and price behind Pedersen commitments and gives the venue
only the second field group (`main.tex:1510`, `main.tex:1537`). **The half of
the paper that measures privacy assumes a more generous settlement than the half
that designs it.** Every result that depends on what settlement publishes ---
the A5 informed-trade detection, the unsettled-request attack, and this
session's block-range argument --- inherits whichever model the code used, and
the paper does not say which.

### 5. A5 reads a field the model does not publish (pre-existing)

`main.tex:1216`: "Detecting from settlements whether a trade was informed is
unchanged (AUC 0.83) in every regime."

`rust/qomm-sim/src/attackers.rs` scores `stl.direction` in the clear. Direction is **not** in
`rust/qomm-sim/src/engine.rs`'s list of what a settled trade reveals, and it is committed
rather than opened under the zkPI. So the attack is run against a settlement
model that neither the simulator's own contract nor the design describes.

The value is also not 0.83 in every regime: generated reactive is 0.810--0.816,
replay 0.828--0.830, UniswapX 0.768--0.775. "Unchanged between matched plain and
QOMM arms" is supported; "0.83 in every regime" is not.

### 6. The obliviousness headline mixes an aggregate with a single cell

`main.tex:1160`: "AUC 0.792 for plain protocols versus 0.500 for the
query-oblivious design with no disclosure."

Aggregating `sim_matrix.json` by protocol, layer and disclosure:

| arm | A_none | B_threshold | C_dp |
|---|---:|---:|---:|
| `plain_rfq` reactive | **0.7799** | 0.7885 | 0.7996 |
| `qomm_rfq` reactive | **0.5000** | 0.5117 | 0.5403 |

The QOMM side is exactly 0.500 and the claim about it holds. The plain side
aggregates to 0.7799; 0.791667 appears in a single raw cell at n=26. **One side
of the comparison is an aggregate and the other is a cell.** The gap survives at
either figure, so this is a reporting defect rather than a wrong conclusion.

The table also shows something the paper does not report: under disclosure the
oblivious arm rises to 0.512 and 0.540, so the exactness of 0.500 is a property
of the no-disclosure arm alone.

### 7. The real-data DP figures do not reproduce, and the profit sign flips

`main.tex:1294`: fill rate pools to `-0.0053 ± 0.0057` and maker profit to
`-27.6 ± 74.1`, "neither excludes zero", the point estimate `7.7x` smaller than
the generated one.

Recomputing from `sim_matrix_bybit.json`, pairing `C_dp` against `A_none` within
each (source, protocol, layer) cell, Student t at n=8 symbols:

| arm | fill rate | maker profit per fill |
|---|---|---|
| `qomm_rfq` reactive | −0.00722 ± 0.00986 | **+29.17** ± 101.13 |
| `qomm_rfq` replay | −0.02521 ± 0.01108 (excludes zero) | **+17.77** ± 68.14 |

And `dp_effect.json`'s own tape arm (LTCUSDT, 12 seeds) gives fill **+0.0185**
(excluding zero) and profit **+80.85**.

Three independent reproductions, all with **positive** profit point estimates
where the paper reports −27.6. The qualitative conclusion --- indistinguishable
from publishing nothing --- survives every one of them, since profit crosses
zero throughout. The quoted numbers do not. `7.7x` does not follow from the
quoted pair either: −0.0344 against −0.0053 is 6.5x.

### 8. The block-range residual is a variance ratio, not a recovery (mine)

`main.tex:2265` says the residual "clears the noise" by 4.7x at six hundred
blocks and is "what the epsilon buys".

`rust/qomm-harness/src/bin/run_block_range_query.rs` fits an ordinary least squares line of distinct
entities on fill count **over the same 400 sampled ranges it then scores**, and
compares the population standard deviation of those in-sample residuals against
the *theoretical* one-answer noise standard deviation. The real-identity arm
**never calls `answer_block_range_query`.** No noisy answer is drawn, no
out-of-sample recovery is attempted, and no maker uses the result for anything.

What the 4.7 supports is that an oracle regression on the free fill count leaves
residual variance well above the noise floor. That is a necessary condition for
the query to be worth its epsilon and not a demonstration of it. The claim needs
to be stated as the necessary condition it is, or an experiment that draws
answers and measures recovery has to be built.

### 9. The abstract attributes RFQ's leakage to RFM and RFS

`main.tex:67`: RFQ, RFM and RFS "leak the existence, direction, size and timing
of a request to every market maker".

`rust/qomm-sim/src/engine.rs`:

```
plain_rfq  asset, size, direction, wallet, time
plain_rfm  asset, size, wallet, time                 (direction withheld)
plain_rfs  asset, wallet, request window             (size withheld)
```

Existence and timing leak in all three. Direction leaks in RFQ only and size in
RFQ and RFM. `sim_matrix.json` bears it out: RFM direction accuracy equals the
prior, and RFS matches the prior on both attributes. The opening sentence of the
paper describes one of its three baselines.

### What is not affected

The circuit costs, the round decomposition, the assembly-from-shares timings,
the settlement state model, the DSL, the multi-asset result and the
threshold-quote proof are untouched by all nine. So is the central claim that a
quorum can prove the opened quote is the registered-policy minimum, which
section 12 fixed and pinned. Six of the nine are reporting defects with the
conclusion intact; 2 is a causal story that has to go; 7 and 8 change what may
be claimed from a measurement that stands.

---

## 16. The Rust port collapsed entities where the Python did not

`lab::build` maps `tape_entities = None` to one entity per observed address and
`Some(n)` to a round-robin collapse into `n`. Python's `lab.build` defaulted the
argument to `None`. The Rust port defaulted it to `Some(24)`.

That is not a cosmetic divergence. It means every Rust tape run collapsed the
addresses a tape shows into twenty-four synthetic firms while the Python it was
ported from kept them apart, so the two languages were not measuring the same
population. The port's own test asserted the collapsed count and recorded, in
its comment, that whether the default should change "moves every tape
measurement, so it is recorded rather than taken here". It was taken here.

### What the tape actually carries

The two tape kinds are not alike, and the earlier code treated them as if they
were.

- **UniswapX** rows carry a real swapper address. An entity *is* an address, so
  per-address is the truth rather than a setting. The Makefile already ran that
  arm without `--tape-entities`, so it was already correct.
- **Bybit** rows carry no identity at all: the loader synthesises `taker:{i}`,
  one per fill. Neither setting is measured there. Per-address asserts that no
  firm ever trades twice; `RoundRobin(24)` asserts a firm count and an even
  split. Both are invented, and the Makefile passed `--tape-entities 24` to
  `rho-sweep`, `dp-effect` and `sim-real`.

### Whether the invented count was carrying the result

Prediction, written before the run: per-address makes each entity appear in
exactly one window, so entity-window incidence becomes sparse and informative
and the attacker should do *better*, not worse; and the per-entity contribution
cap stops binding, so the disclosure should get *more* accurate. Both arms move,
and the thing to check is whether the ordering moves with them.

`LTCUSDT2021-06-15`, one seed, 411 requests, passive observer:

| rho | `plain_*` AUC at 24 | `plain_*` AUC per address | `qomm_rfq` at 24 | `qomm_rfq` per address |
|---:|---:|---:|---:|---:|
| 0.00 | 0.5000 | 0.5000 | 0.5000 | 0.5000 |
| 0.25 | 0.6172 | 0.6382 | 0.5000 | 0.5000 |
| 0.50 | 0.7344 | 0.7886 | 0.5000 | 0.5000 |
| 1.00 | 1.0000 | 1.0000 | 0.5000 | 0.5000 |

The predicted direction holds and is small. The prediction that the collapse
would saturate the positive class and flatten the baseline to 0.5 was wrong ---
it tracks rho at twenty-four as well, just less steeply. `dp_effect`'s paired
intervals include zero in both settings at six seeds.

So the ordering is identical: every baseline rises with the adversary's prior
knowledge and the query-oblivious arm holds at exactly 0.5000 throughout. The
invented firm count was not carrying the conclusion, and the gap is in fact
wider under the setting that assumes less.

### What was changed

`tape_entities` now defaults to per-address in the Rust library, in
`run_rho_sweep` and `run_dp_effect` in both languages, and `--tape-entities 24`
is gone from the `sim-real` target. The Rust `run_rho_sweep` and `run_dp_effect`
could not express per-address at all --- they held a `usize` --- so both now
hold an `Option<usize>`.

The test that asserted the collapse now asserts the opposite, and it is
load-bearing: restoring `Some(24)` makes it fail at `tapes.rs:155`. Against the
Python with identical arguments, `rho_sweep` agrees on 280 of 280 non-timing
values and `dp_effect` on 122 of 122, both reporting 411 entities and
`one entity per observed address`.

### The same divergence again, in a script whose acceptance had passed

`run_block_range_query.rs:107` did not read the default at all --- it passed
`Entities::RoundRobin(24)` as a literal, where the Python calls
`lab.build(tape=...)` and takes whatever the library default is. That agreed
with the Python only for as long as the Python's default was also twenty-four,
and this script had been through a Python-against-Rust acceptance comparison
that reported no differences. The comparison was run while both were
twenty-four, so it could not have found this.

The gap is not small. On `LTCUSDT2021-06-15` at three seeds the two disagreed on
277 values: the Bybit arm saw 4,331 entities per address against 24 collapsed,
and the width at which the distinct count reaches 95% of the entities seen moved
from 2 windows to 39. With the literal replaced by `Entities::PerAddress` the
two agree on 1,220 of 1,220 non-timing values.

A hardcoded constant that happens to equal a default is not a port of that
default, and an acceptance run cannot distinguish them while the two coincide.

---

## 17. Python stopped adding floats the obvious way, and the port had not noticed

Comparing `run_sim_matrix` across the two languages left 23 values disagreeing.
All of them were correlations, and all of them disagreed in the sixteenth
significant digit --- `0.2538502992501242` against `0.2538502992501243`. That is
the shape of a summation difference, not of a wrong computation, which is
exactly why it had survived: every printed form of these numbers is identical.

There are two causes, and they are different from each other.

**`statistics.fmean` is not a naive mean.** It is `math.fsum` and one division,
and `fsum` is exactly rounded --- Shewchuk's algorithm, every partial kept. The
port computed `a.iter().sum::<f64>() / n`.

**The builtin `sum` is not a naive sum either, and has not been since CPython
3.12.** It carries a Neumaier compensation term, so `sum([0.1] * 10)` is exactly
`1.0` where a left-to-right fold gives `0.9999999999999999`. Every `sum(...)`
over floats in the Python being ported therefore has compensated semantics.

The two are not interchangeable. Routing everything through `fsum` because it is
the more accurate of the two would be a different function from the one being
ported, and would leave the same class of silent disagreement pointing the other
way. `qomm_sim::fsum` now carries both, `fsum` and `nsum`, pinned by a test
against values typed in from a real interpreter rather than derived in Rust.

`pearson` needed both at once: its two means are `fmean`, and its three
sums-of-products are the builtin. With each routed to the one the Python
actually uses, the same comparison gives 379 non-timing values identical and 0
different.

### Where else it reached

The same substitution was applied at every site whose Python counterpart sums
floats: `engine.rs` markout means, `report.rs`'s least-squares fit and its
$R^2$, `derive_snr.rs`'s weighted mean size and its drawn medians,
`run_deccp.rs`'s per-order verification mean, and `run_disclosure_ceiling.rs`'s
other-maker P&L. `run_block_range_query.rs` sums integer errors, which is exact
either way, and was left alone.

This is the third divergence today whose common shape is a Rust expression that
*looks* like the Python next to it. A hardcoded `24` that equalled a default, a
`RoundRobin` that should have read one, and a `.sum()` that is spelled the same
as `sum()` and is not the same function.

---

## 18. The approval gate could not load its own output

`serve_qomm` is the resident quoting service, and `--approved` is what decides
which circuits it will run at all: a shape not in the file is refused rather than
compiled. `--approve-into` writes that file. The two did not fit together.

A shape is a sequence of `(name, value)` pairs. `--approve-into` writes it as
`list(key)`, so JSON renders each pair as an array. `--approved` reads it back
with

```text
registry._approved[tuple(entry["shape"])] = _entry_from(entry)   # retired service predecessor
```

`tuple(...)` converts only the outer level. The elements stay lists, a list is
unhashable, and using the result as a dict key raises
`TypeError: unhashable type: 'list'`. Reproduced in three lines against the exact
key the retired service predecessor built:

```
written: [{"name": "shape0", "program_digest": "deadbeef",
           "shape": [["n_mm", 1], ["n_parties", 3], ...
ROUND TRIP FAILS: TypeError unhashable type: 'list'
```

So the service could never be started from an approval file it had produced, and
the only two ways to run it were with no gate at all or with a hand-written file
in a format nothing generated. Nothing exercised the path, which is why it
survived: the crash is at start-up, before the port is bound, so it does not look
like a service fault.

**What the Rust does instead.** It writes the same bytes --- the array of pairs
is the format that was already on disk --- and keeps the shape as a JSON value
compared by equality rather than used as a hash key. So an approved file from
either side loads. That is a deliberate difference from the Python and not a
port of it, which is the reason to say so here.

`an_approved_file_loads_back_the_shape_it_was_written_from` pins both halves: the
round trip, and that the on-disk form is still an array of pairs rather than an
object. Changing `Request::shape()` to return the object it builds internally
makes it fail on the second assertion, which is the drift it exists to catch.

---

## 19. What the sandbox had been hiding

Ten of the ported measurement scripts had never been compared against the Python
they replace. Every one of them drives MP-SPDZ, the agent doing the porting ran
sandboxed, and a sandboxed process cannot `bind(2)` the port block a party needs.
So the report said "could not run end to end", which was true, and the ports were
carried on the strength of the code reading correctly.

They were run on a machine with the engine built and no sandbox. Eight of the ten
could be run there; `run_placement` needs a second host and `run_evm` needs an
Ethereum archive node.

| script | non-timing identical | different |
|---|---:|---:|
| `run_multiplication_cost` | 27 | 0 |
| `run_robust_atlas` | 65 | 0 |
| `run_multi_asset` | 165 | 0 |
| `run_rounds` | 240 | 0 |
| `opt_sweep` | 38 | 0 |
| `run_identity` | — | — |
| **`sweep`** | 37 | **3** |
| **`run_three_times`** | 14 | **1** |

Six agree exactly. Two do not, and both disagreements reproduce: two independent
runs gave the identical wrong value.

### `sweep` reveals a different quote from the same circuit

```
/returncode:     0 vs 1
/verified:       True vs False
/verify_detail:  got=(1152921504606846976, 0) want=(1152921504606846976, 0)
              vs got=(10357048172212131266, 1) want=(1152921504606846976, 0)
```

Everything describing the circuit is identical across the two: 829 integer bits,
9 integer opens, 793 integer triples, 31 VM rounds, 45 measured rounds, 0.398184
MB for party 0 and 1.43587 MB globally, on the same protocol, party count,
threshold, bit length and field width. The same program ran at the same cost, and
MPC cost is data-independent, so the difference is in what was fed in.
`1152921504606846976` is $2^{60}$, the value both sides say they expect; the
Python reveals it and the Rust reveals a larger number with the companion flag
set. On the Rust's inputs some maker is eligible where on the Python's none is.

`run_three_times` disagrees on `audited_rfs_met`, which is also a predicate over
maker eligibility. Whether that is the same cause is being established rather
than assumed.

### The part that is about method rather than about these two bugs

An acceptance comparison that cannot be run is not a weaker form of evidence, it
is the absence of evidence, and the summary table that carried these ten ports
recorded exactly that. What it could not do was say how much was riding on it.
Two of eight is a rate worth knowing before deciding that an unrunnable check is
acceptable for the remaining two.

The reason the check could not run is also worth naming: the sandbox that blocked
`bind(2)` was chosen by the caller, not required by the task. The engine had been
built successfully in the same session.

### What the two disagreements turned out to be

**`sweep` was a decoding bug, not an input one.** The reasoning that the inputs
must differ --- same circuit, same cost, different revealed value --- was sound
but incomplete: the third possibility is that the same revealed value is read
differently, and that is what happened. The RFQ verification subtracts a
one-time mask from the opened key before unpacking it. The mask for this
configuration is `18408253335210568581`, which is larger than `i64::MAX`, and the
reference parser reached for `as_i64` only. It got nothing, treated the mask as
zero, and unpacked the still-masked key:

```
correct:   20714096344424262533 - 18408253335210568581
         = 2305843009213693952,  unpack(padded=2) -> (1152921504606846976, 0)
as built:  unpack(20714096344424262533, 2)         -> (10357048172212131266, 1)
```

Both are `i128` arithmetic; the loss was entirely in reading a `u64` out of JSON
through a signed accessor. `rfq_verification_subtracts_a_mask_above_i64_max`
pins it with the real mask value, and removing the `as_u64` fallback makes it
fail.

Byte comparison of the generated `prog.mpc` and every `Input-P*-0` for both
failing configurations found no difference, which is what closed off the input
hypothesis rather than leaving it merely unlikely.

**`run_three_times` was the build profile, and then the threshold.**
`audited_rfs_met` is not an eligibility predicate at all; it is
`total.mean <= 1000 ms`. The comparison was running the Rust out of
`target/debug` while the Python calls optimised native libraries, so the same
work took 9,319 ms against 977 ms and the flag turned over on that alone.

The first fix offered was `[profile.dev] opt-level = 3` in the workspace
manifest. That is the wrong place: the Makefile builds every measurement
`--release`, so nothing in the repository was affected --- the mistake was in a
throwaway comparison script reaching into `target/debug`. It has been reverted,
the script now prefers the release binary, and `timing_summary` says once on
stderr when it is summarising durations from a debug build, so the next person to
make that mistake is told rather than left to infer it from a number.

The predicate itself is excluded from the comparison, for a reason worth stating
precisely: it is a threshold on a duration and inherits the duration's
nondeterminism. On a loaded machine the *Python alone* was observed at 976.9 ms
and 1007.0 ms, on opposite sides of its own threshold. A boolean like that cannot
be compared between two runs whatever the language, and skipping it as a
derived duration is honest where skipping it as "a difference we could not
explain" would not be.

### The eight, re-run against release binaries

| script | non-timing identical | different |
|---|---:|---:|
| `run_multiplication_cost` | 27 | 0 |
| `run_identity` | 17 | 0 |
| `run_robust_atlas` | 65 | 0 |
| `run_multi_asset` | 165 | 0 |
| `run_rounds` | 240 | 0 |
| `sweep` | 40 | 0 |
| `opt_sweep` | 38 | 0 |
| `run_three_times` | 14 | 0 |

`run_identity` needed one more exclusion, and it is worth the paragraph because
the reason had to be established rather than named. Its `honest/openings` are
blinded, so they are fresh on every run: two consecutive runs of the *Python*
give different numbers for them while agreeing on the challenge that produced
them. A value that a single implementation disagrees with itself about cannot be
evidence about a port, in either direction. Running the Python twice is what
turned that from a guess into a fact, and it is cheaper than arguing about it.

The three exclusions the comparison now makes are therefore of three different
kinds, and collapsing them into "timing" would have been wrong: a duration, a
threshold on a duration, and a value that is freshly randomised per run.

---

## 20. Sixteen makers into eight slots

Closing the aggregate proving API turned up something the API was not the point
of. The Rust refuses to prove a quote when `n_slots` is smaller than the number
of makers; the Python never checked; and
the predecessor of `rust/qomm-harness/src/bin/run_threshold_assembly.rs` set `n_slots=8` whatever `--makers`
says, while the Makefile asks for `--makers 2 4 8 16`.

So the checked-in `threshold_assembly.json` has a sixteen-maker row measured in
eight slots, and the paper cites it: `check_numbers.py:187` pins
`quote[16]["verify_over_local"] == 1.18` and `main.tex:975` writes it out as
"to 16 makers --- and 1.18x to verify".

### Why eight slots cannot hold sixteen makers

A maker is ranked by `key = (gated + sentinel) * n_slots + index`, and the
verifier rebuilds it in the exponent from that maker's own gated commitment and
its own index:

```rust
let derived_key = (c.gated + key.commit(&scalar(public.sentinel), &Scalar::ZERO))
    * scalar(public.n_slots)
    + key.commit(&Scalar::from(index as u64), &Scalar::ZERO);
```

That is a bijection on `(cost, index)` only while `index < n_slots`. Past it the
packing wraps: at `n_slots = 8`, maker 8 at gated cost `c` and maker 0 at gated
cost `c + 1` pack to the same integer, `5*8 + 8 = 6*8 + 0`, and because the
generator is the same one, they derive the *same group element*. Two different
makers at two different costs rank as one key, so a proof that the opened key is
the minimum no longer says whose it is.

Nothing catches this at run time, on either side. The prover and the verifier
compute the same wrapped packing, so the proof verifies and the Python's
`assert ok, why` passes. It is self-consistent and it does not mean what it says.

`slot_collision.rs` pins both halves: the two derived key commitments are equal
at eight slots and distinct at sixteen.

### What was changed

The measurement now takes one slot per maker, floored at the eight the earlier
rows used, and uses the same count for every row so the rows stay comparable.
The maker-count ceiling in the binary is gone with it --- it was a symptom
written as a limit.

Both pinned numbers move, because the span the range proof covers moves with
the slot count. They are re-measured rather than adjusted.

---

## 21. The per-node cost was measured before the construction checked itself

Re-running `run_threshold_assembly` to re-pin the numbers the slot change moves
turned up something larger. The paper says a node assembling a threshold proof
pays about what a local prover pays:

> `check_numbers.py:184` pins `per_node_over_local` at **1.06** across every
> maker count, and `:175` at **1.09** for the width-26 range proof.

Neither implementation produces those numbers now. On one host, at one load,
with the same widths, the same maker counts and the same slot count:

| | checked-in artifact | Python today | Rust today |
|---|---:|---:|---:|
| width 26, `per_node_over_local` | 1.0942 | **14.79** | **14.87** |
| width 26, assembled bytes | 5,088 | 5,088 | 5,088 |
| 8 makers, `per_node_over_local` | 1.0569 | **14.34** | **14.19** |

The two languages agree with each other to about 1%. It is not the port.

### What changed

`artifacts/threshold_assembly.json` was last written at `09647a4`, "The whole
quote proof, assembled by a quorum that holds no witness". `rust/qomm-proofs/src/threshold_gadgets.rs`
has been committed to three times since, and is dirty again in the working tree.
What those changes added is the checking:

```
+    def check_opening(self, dealer: int, ...
+                           share_commitments: Mapping[int, Any],
+    the published coefficient ladders, so a verifier runs this without holding a
+    for party in entry["quorum"]:
+                          group.point_pow(share_commitments[party], challenge))
```

A group exponentiation per quorum member per bit, plus the Pedersen VSS ladder
check a recipient runs against the published coefficient commitments. Those are
the fixes that made the assembly sound --- the constant-opening API is gone, a
recipient verifies its own share, a bad contribution names its node --- and they
cost about fourteen times what the construction cost without them.

So the claim as pinned is not that threshold assembly is cheap. It is that
threshold assembly *was* cheap before it verified anything.

### What is actually true, and it is not nothing

At width 26 the Rust assembles in 203.7 ms of total CPU across a quorum of
three, so **a node spends about 68 ms**, against 4.6 ms to prove the same
statement locally and alone. The assembled proof is still *smaller* than the
local one --- 5,088 bytes against 5,920, 0.859x --- and that is unchanged. The
honest sentence is that a node pays tens of milliseconds and roughly fifteen
times a solo prover for a proof no single node could have made, not that it pays
about the same.

`verify_over_local` moves too, and for a different reason: the Python gives 1.18
and the Rust 2.53 on the same input. Both are ratios *within* one language, and
the two languages have different relative constants --- the Rust is faster at
both sides and less lopsidedly so on the assembled one. With Rust as the record
the number is 2.53, and it is a language fact rather than a defect.

Every pin these touch has to be re-measured with the load off the host, not
adjusted.

### What was written down instead

The measurement was retaken on an idle host at fifteen repeats, and the artifact
now records `n_slots` --- because that is a soundness parameter and not a tuning
one, and an artifact whose maker count exceeds it has measured a run in which two
makers share one ranking key.

The pins changed shape as well as value. A ratio of two medians is not a
two-decimal quantity: two clean runs of the same binary on the same idle host
gave 14.27 and 14.99 for the width-26 per-node cost. So the ratios are bounded
and the *sizes*, which are exact and did not move, carry the precision:

```
threshold range: per-node cost is about fifteen local provers   14 <= x <= 16
threshold range: the assembled proof is smaller                 5088 bytes
threshold range: the local proof it replaces                    5920 bytes
threshold quote: and flat means within a tenth across sixteen makers
threshold quote: every maker has its own ranking slot           max(makers) <= n_slots
threshold quote: CPU across the quorum at sixteen makers        10993 ms
threshold quote: what one node pays                             3664 ms
threshold quote: what proving it alone costs                    247 ms
```

The three absolute figures are pinned because the prose now carries them, and a
sentence with no pin behind it is worse than a failing check --- the old
paragraph's `1.06` and `1.18` were exactly that for as long as it took to notice.
`make check` is at 131/131.

---

## 22. "Identical to the Python" was always identical to *a build* of it

`run_dp_audit` compared clean on the laptop and did not on the measurement host.
On host-a the two implementations disagreed on 81 values out of 3,231.

Every one of them was `empirical_epsilon` or the maximum of a group of them. No
boolean, no integer and no threshold differed --- so the best threshold chosen,
the number of violations and `within_claim` were the same on both sides --- and
the worst relative difference was $2.04\times10^{-13}$, against a claim tested
with $10^{-9}$ of slack.

### Where it comes from

`empirical_epsilon` is `log(num/den)` over Clopper--Pearson bounds, which come
from an inverse regularised incomplete beta by bisection. Both `log` and the
bisection agree bit for bit. The same eight `beta_ppf` inputs give:

| | agreeing | differing |
|---|---:|---:|
| laptop, macOS arm64, CPython 3.13.5 | 8 | 0 |
| host-a, Linux x86_64, CPython 3.12.3 | 5 | **3** |

CPython's own `lgamma` is *not* the variable: it returns identical bits on both
machines for the same inputs. What changes is the Rust. `qomm-sim/src/audit.rs`
computes the Lanczos tail with `mul_add`, and its comment says why:

```
// CPython's C build contracts this multiply-add; spelling it explicitly
// preserves the installed interpreter's last bit in release and debug.
```

That is true of the interpreter it was written against and not of the one on the
measurement host. `mul_add` rounds once where a separate multiply and add round
twice, so the Rust is if anything the more accurate of the two --- the residue is
CPython's second rounding, not an error here.

### The part that generalises

Every "byte-identical" and "0 different" in this document was measured on some
machine against some interpreter, and this is the first time that qualifier has
had to be written down. A port verified against one build is verified against
one build. Nothing was wrong with the checks; what was missing was the sentence
saying what they were relative to.

It also has an expiry date. Matching CPython is a requirement only while there is
a CPython to match: once it is deleted the constraint is accuracy and
determinism, and `mul_add` is then simply the better implementation with no
counter-argument left.

---

## 23. The language guard was a list of file extensions

`export_repos` is what keeps the public repositories English, and the comment
above the check says so plainly: "This is checked rather than remembered: the
working tree is written in two languages and the boundary between them is
exactly the export, so the export is where it is enforced."

It was remembered after all. The predecessor applied the scan to an allowlist
of fourteen suffixes. The Rust exporter now attempts UTF-8 decoding for every
exported file and scans every file that decodes, independent of suffix.

Sixty-one of the six hundred and twenty-one exported files have a suffix that is
not on it, and they are not marginal ones:

| never scanned | files |
|---|---:|
| `.go` --- the whole Avalanche VM | 23 |
| `.data` --- binary test fixtures | 14 |
| `.lock` | 6 |
| `.sol` --- the Solidity contracts | 4 |
| `.law`, `.rule` --- the DSL sources | 6 |
| `.html`, `.css`, `.js`, `.cpp`, `.service`, `.mod`, `.sum` | 8 |

Scanning the exported trees directly rather than trusting the check found one
file with Japanese in it, and it is not an accident: `qomm_demo/static/demo.js`
is `S = {ja: {...}, en: {...}}` with a language toggle, so the demo is bilingual
on purpose and its ninety Japanese lines are a feature. Nothing else carried
any --- which is luck, not enforcement. A Japanese comment in the VM would have
shipped and nothing would have said so.

### What was changed

Both implementations now scan **everything that decodes as UTF-8**, and the
extension list is gone. Binary files fail to decode and are skipped, which is
what the fourteen `.data` fixtures are. The demo is a named exception,
`JAPANESE_BY_DESIGN`, so that it is a decision somebody took rather than a hole
in a list.

Watched failing before being believed: a Japanese comment appended to
`avalanche/defmivm/factory.go` --- a file the old guard never opened --- gives

```
PROBLEM defmi/avalanche/defmivm/factory.go: Japanese on line 17
```

from both implementations, both exiting 1. The probe was then removed and the
tree checked clean.

### The general shape, for the fourth time today

A hardcoded `24` that equalled a default, a `.sum()` that is spelled like
`sum()`, a `mul_add` that matched one interpreter build, and now an allowlist of
extensions standing in for "text". Each was a rule expressed as a list of the
cases somebody had thought of, sitting next to a comment claiming the rule
itself.

---

## 24. A test suite does not survive a change of runner

Porting `tests/` to Rust took the count from 570 `#[test]` to 751, and the
workspace then failed on the measurement host and passed on the laptop:

```
tests::every_relay_hop_costs_a_connection ... FAILED
  left: Number(67)   right: Number(72)
```

Five of seventy-two frames had not been delivered.

### What it was not

Not the parameters, though those were wrong too and were fixed: the Rust ran
four slots with a 5 ms link delay where the test now embedded in
`rust/qomm-harness/src/bin/run_transport.rs` runs eight slots
and none, and three hops at 5 ms against a 10 ms slot is a race the delay
always wins. Correcting that made it flake instead of fail.

Not the build profile: `cargo test --release` failed three runs out of five.

Not the transport: the release *binary*, given exactly the same options,
delivered 144 of 144 frames on eight consecutive runs, and the Python passed
five out of five on the same host.

### What it was

`cargo test` runs a module's tests in parallel threads. The retired test runner
ran them one after another. Three tests in that file each drive a wall-clock slot schedule
over real loopback sockets, and two of them at once contend for the CPU until
frames miss their 10 ms slot.

| | passes |
|---|---|
| `cargo test --release` | 2 of 5 |
| `cargo test --release -- --test-threads=1` | **6 of 6** |
| after taking a process-wide lock, parallel again | **6 of 6** |

The three now take a `static Mutex` before they start their clock.

### Why this one is worth the section

Every other divergence found today was a value: a constant, a summation, a
rounding mode, a field width. This one is a property of the *harness*, and no
comparison of two implementations could have surfaced it, because both
implementations were right. A suite that measures time was moved from a
sequential runner to a parallel one, and nothing in "640 assertions became 751"
says so.

It also only appeared on the machine the measurements actually run on. The
laptop is fast enough to hide it, which is the worst place for it to be hidden.

---

## 26. The Python is gone

`find . -name '*.py'` under this directory returns nothing --- the boundary is
this directory, and the one Python outside it that is ours is named below. What
replaced it was checked before it replaced anything: every one of the 62
measurement scripts, the three under `zk/` and `evm/`, and the 640 test
assertions were compared against the Python value by value while both existed.
The workspace is 759 `#[test]`, passing on this laptop and on the measurement
host.

The three published repositories were rebuilt rather than trimmed. Each now
ships `qomm-harness` carrying only the binaries that repository names, with a
generated manifest, because the alternative --- shipping the whole harness
everywhere --- would put the DeFMI measurements in `zkpi`, and listing the
runners one by one is exactly what the Python did.

| repository | files before | after | tests, run from inside the exported tree |
|---|---:|---:|---:|
| zkpi | 84 | 85 | 249 |
| defmi | 177 | 209 | 484 |
| qomm | 368 | 330 | 478 |

Verified independently of the exporter's own report: the three trees were
exported, entered, and `cargo test --workspace` run inside each. No `.py` in any
of them, none of the eight real machine names, and Japanese in exactly one file
--- `qomm_demo/static/demo.js`, the demo's declared bilingual locale.

### Oracles that could not survive their subject

Five tests took their expected values by running the Python. With the Python
deleted those are not weaker tests; they are not tests, because an oracle that
has been deleted cannot disagree with anything. Each was recovered from the last
commit that carried it and pinned:

| where | what was pinned |
|---|---|
| `qomm-harness/src/measure.rs` | the whole public contract of `scripts/measure.py` |
| `qomm-measure/src/hosts.rs` | the retired reader's contract |
| `qomm-mpc/tests/program_parity.rs` | six generated programs, by length and SHA-256 |
| `qomm-mpc/tests/all_files_parity.rs` | 27 cases: outputs, status, stdout, stderr, file bytes |
| `qomm-harness/src/bin/zk_bench.rs` | the `platform.machine()` shell-out |

The first was pinned by hand and checked load-bearing --- one digit changed in
the recorded JSON makes it fail. The rest were found by asking for others of the
same shape, which is the only way to find them: they do not fail, they stop
meaning anything.

### What still runs Python

`MP_SPDZ_ROOT/compile.py`. MP-SPDZ's compiler is Python and belongs to MP-SPDZ.
Any claim that this repository is Rust is about this repository's code; the
pinned dependency still brings its own toolchain, and a measurement that compiles
a circuit still invokes it.

The two notebooks are held. `evcxr` is a Rust kernel for Jupyter, so they can
stop being Python without stopping being notebooks, which deleting them would
not achieve.

The paper's build chain is Python and stays Python: `check_numbers.py`,
`make_appendix.py` and `make_revtex.py` under `papers/qomm/`, 1,909 lines that
generate a LaTeX appendix from the artifacts, rewrite the body into a
two-column layout, and check 140 numbers in the documents against the artifacts
they cite. None of the three produces a measured value; they read the artifacts
this repository writes and emit or verify a document. The claim worth making is
that the numbers are Rust-measured, and that claim does not weaken because the
checker that reads them is not.

---

## 27. One harness asked the machine its name itself

The re-measurement wrote the measurement host's own node name --- not its
label --- into four `clob_baseline_clean_d*.json` and into the manifest. The rule against that is
old and it is written down: `hosts::this_host()` exists to apply it, and sixteen
harnesses call it. The seventeenth, `run_clob_baseline`, carried its own four
lines:

```rust
fn hostname() -> io::Result<String> {
    let output = Command::new("hostname").output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
```

which is `hosts::node_name()` with the labelling step left out. It had exactly
one caller, and that call sat in a literal beside `n_parties` and `threshold`,
where nothing about it looked like a decision.

The existing guard, `no_real_machine_name_appears_in_a_file_that_ships`, did
catch it --- but only after the leak existed. It reads the private table and
scans the shipped tree, so it can say nothing until a run on a *named* machine
has already written the name into an artifact. Written on a laptop, or on any
machine absent from the table, the offending four lines pass every test in the
workspace. The artifacts here were written at 02:58 and the guard first failed
at 09:40, which is not the guard being slow; it is the guard being unable to
speak earlier.

So it was joined by one that states the rule rather than waiting for a
violation of it: `only_this_reader_asks_the_machine_its_name` fails if any
shipped `.rs` outside `hosts.rs` constructs a `hostname` command. Checked
load-bearing --- putting the four lines back makes it fail, taking them out
makes it pass.

### The general shape, for the fifth time

A hardcoded `24` that equalled a default, a `.sum()` spelled like `sum()`, a
`mul_add` that matched one interpreter build, an allowlist of extensions
standing in for "text", and now a private `hostname()` standing in for the
labelled one. The four earlier ones were a rule expressed as a list of the cases
somebody had thought of. This one is worse in one way and better in another: the
rule was not a list, it was a function, and the function was correct --- what
failed is that nothing prevented writing a second one. A rule enforced by a
helper is only enforced where somebody chose to call it.


### The writeup leaked what the fix had stopped leaking

The first draft of this section named the machine. `REVIEW.md` is exported to
all three repositories, so that draft shipped the string the four artifacts had
just stopped shipping --- and the guard said nothing, because the set it scanned
was a list of thirteen top-level directories. Seven of those were the Python
packages and no longer exist. None of them was the repository root, where every
`.md` the exporter publishes lives.

The list is gone. `shipped_files` now walks the repository and excludes what is
built or pulled, so it is a statement about the repository rather than about
what somebody remembered was in it. It caught the probe: putting the name back
into `REVIEW.md` fails the guard, taking it out passes. It also got faster,
because the old list swept 189 MB of tapes looking for a hostname.

That is the fifth and sixth instance of the shape in one review, and the sixth
was written by the hand that was fixing the fifth.

### Why the artifacts were relabelled and not re-measured

`host` is provenance, not a measurement. `label()` of that node name is a
lookup in `scripts/host_map.txt`, and `host-a` is exactly the string the fixed
code writes on that machine --- so the edit restores the value that should have
been recorded rather than substituting a plausible one. The remaining 130
artifacts already said `host-a`, which is what made the four visible. The
manifest was regenerated and `manifest --check` reports 134 artifacts matching;
`check_numbers.py` stays at 140/140, `host` being nothing any pin reads.

---

## 28. One failure, once, and it is still not explained

The full workspace run on the laptop failed one test:

```
executor::tests::verified_handle_survives_path_replacement_before_spawn
  assertion failed: output.status.success()
```

It is the test for the defence that makes a verified program unswappable: the
executable is hashed through an open handle and then run as `/bin/sh
/dev/fd/N`, so renaming the path between the hash and the spawn cannot change
what executes. The same test passed in the same run on the measurement host,
and has passed in every run since --- alone, then six times with its crate,
then one more full workspace run on the laptop.

What was ruled out: the descriptor limit, which was the obvious candidate for a
failure that appears only when 174 test binaries run at once. It is 1,048,576
on this laptop, so nothing here was near it. What remains suspect is macOS's
`/dev/fd`, which is not Linux's. On Linux `/dev/fd/N` re-opens the file and the
reader starts at zero; on macOS it duplicates the descriptor and shares the
offset with the handle the parent still holds --- which `open_verified` already
seeks back to zero for, deliberately. A shared offset makes a *second* spawn
from one verified handle read from EOF and run an empty program silently, on
macOS only. That is not what this test does, and it is not a hypothesis this
failure confirms; it is the one difference in the mechanism that is real, and
it is written down here so the next occurrence is read against it rather than
from scratch.

The assertion was `assert!(output.status.success())`, which says nothing when
it fires --- not the exit status, not what the shell printed. It now carries
all three. That change is worth keeping whether or not the failure returns: a
test that cannot describe its own failure costs a full re-run to learn what one
line could have said.

Recorded rather than closed. Two runs that pass do not explain one that did
not.
