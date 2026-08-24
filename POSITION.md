# What is new here, and what is not

Every mechanism in this stack has a paper behind it, and for most of them the
paper is older than the stack. That is not a problem to hide; it is the thing to
be precise about, because a reviewer finds it in an afternoon and the only
question is whether we found it first.

Five pieces of prior work are compared here. All five have been read from the
paper rather than the abstract page. **The position is an applied one** --- no
new primitive, no security proof, no better asymptotic. What is claimed is a
composition, the measured cost of every link in it, and a small number of
findings that only appear once it is built.

---

## 0. At a glance

**In one sentence.** Every prior work audits *"the circuit was evaluated
correctly."* This audits *"this was the best price of those offered"* --- and
then carries the same unopened commitment into settlement, so the trade clears
at that price without anyone learning it.

Six axes separate the six systems. Read the columns.

| | **2014** Baum–Damgård–Orlandi | **2020** Baldimtsi et al. | **2022** Rivinius et al. | **2023** Prime Match | **2026** Baum–Zok | **here** |
|---|---|---|---|---|---|---|
| **who computes** | dishonest maj. | dishonest maj. servers | threshold `t` of `n` | 2 parties + hub | dishonest maj. | **honest maj. `T=2/7`** |
| **inputs from separate parties** | no | **yes**, and corruptible | **yes**, and corruptible | yes (clients) | no | **yes** |
| **what the audit gives** | exact correctness | **approximate** (spreading relation) | exact **+ blame + robustness** | *none* | exact correctness | exact correctness |
| **commitment rests on** | DLOG | DLOG, subexp. | lattice | — | **random oracle** | DLOG (VOLEitH measured) |
| **what is audited** | the circuit | the circuit | the circuit | — | the circuit | **the market mechanism** |
| **private settlement** | no | no | no | no | no | **yes** |
| **implemented / measured** | partly | **no** | **yes** | **production** | **no** | prototype, measured |

Two rows carry the argument. **"what is audited"** is where this differs from
all five. **"private settlement"** is where it goes somewhere none of them do.
Everything else is a choice of regime, and on most of those axes somebody else
is stronger.

### The three claims this does not make

Each was claimed in an earlier draft of this repository and is now retracted.

| retracted claim | whose it is |
|---|---|
| this makes MPC publicly auditable | Baum, Damgård, Orlandi, SCN 2014 |
| VOLE-in-the-Head commitments are a new route to post-quantum auditable MPC | Baum and Zok, `eprint 2026/337`, Feb 2026 |
| this is the first secure computation deployed in finance | Prime Match, J.P. Morgan, 2023 |

### What auditability costs, which is the number to compare

Everyone in this line pays something to make the outcome checkable. Only two of
the six measured it.

| | what it buys | measured cost |
|---|---|---|
| **Rivinius 2022** | public verifiability **+ accountability + robustness** | **11x to 20x** the online phase against plain SPDZ; 17.48 MiB against 3.61 |
| **here** | public verifiability | **1.07x** wall clock, **2.00x** traffic, **1.00x** rounds |
| **Goyal–Song–Zhu 2020** | robustness alone, at `t < n/3` | **5.5 to 7.5** elements per party per multiplication --- *less than the 8.0 this stack's online phase already spends* |

**The gap is not a result about who built it better.** It is where the audit
attaches. Rivinius commits to every share of every wire, so the commitment
scheme is inside the multiplication. Here the commitment is to a maker's
*policy*, and one proof afterwards shows the mechanism was applied to it, so
the MPC only has to run in a wider field --- which is `2.00x` traffic and
nothing else. **Their construction also delivers blame and robustness; this one
delivers neither.** Both halves belong in the comparison --- though the third row
says the robustness half is an unbuilt saving rather than a design limit, and
`ACCOUNTABILITY.md` is why.

---

## 1. The claim

> A request-for-quote market can be run so that no participant --- the venue
> included --- learns a maker's pricing policy or the losing quotes, while
> anyone can verify afterwards that the quote returned was the best of those
> submitted and that the trade settled at that price. The contribution is the
> composition and the measured cost of every link in it, including the links
> that turned out to be unaffordable.

---

## 2. Baum, Damgård, Orlandi (SCN 2014) --- where the mechanism comes from

**Theirs.** Input providers publish Pedersen commitments. The SPDZ online phase
is nothing but openings of linear secret sharings, so if every message goes to a
bulletin board an auditor replays the same linear operations on the
*commitments*. Privacy needs one honest party; **correctness survives all
parties being corrupt.**

**That is the construction `quote_proof.py` instantiates** --- not a variant, not
a rediscovery.

Six differences. Only two are cryptographic.

**2.1 The corruption model is the other one.** They are dishonest majority. This
is honest majority, Shamir over seven nodes, `T = 2`, malicious. That is a
weaker assumption about the world, and it buys an information-theoretic online
phase with no MACs, which changes what the audit attaches to. Their correctness
survives all seven colluding; so does the quote proof's. **Privacy here does not
survive three.**

**2.2 The input parties are not the computing parties.** A maker deals its
policy to seven nodes and is not one of them. In 2014 --- and, explicitly, in
2026/337 --- the input providers *are* the computing parties. That separation is
what creates the gap this repository is about: `roles.py` proves a node received
a committed share and cannot prove the node fed that share to MP-SPDZ.
**Sections 3 and 4 are the two works that do separate them**, and it is a
difference from 2014 rather than from the field.

**2.3 The field problem is theirs too, and here it is a number.** Their own
successor summarises them as instantiable "only ... over fields as large as
Discrete Logarithm-hard groups". That is section 1 of `BINDING.md`, written
independently and then found in the literature --- the right order, not the
flattering one. What is not in any of these papers is what it costs:

| | ratio |
|---|---:|
| rounds | **1.00x** |
| traffic | **2.00x** --- the element width, 16 bytes to 32, and nothing else |
| wall clock at 15 ms RTT | 1.07x |
| wall clock at 120 ms RTT | 1.06x |

Cheaper cross-region than in a datacentre, because rounds do not move and round
trips dominate there.

**2.4 The audited statement is a market statement.** Their auditor checks the
output is the correct evaluation of the circuit. `quote_proof.py` proves:

> for each maker `i`, `key_i` is the committed policy applied to the committed
> request, and the opened winner is the smallest of those keys

Minimality plus membership is exactly best execution. 152 ms to prove and 173 ms
to verify at four makers, 307 and 350 at eight (`host-a`). **That the statement
is about best execution rather than about circuit correctness is a choice in how
the circuit and the proof are cut**, and it is what makes the artifact usable by
someone who has not read this document.

**2.5 The output has to settle**, and their story ends at the output. Section 7.

**2.6 What is published is deliberately noised.** The quote is disclosed under a
differential-privacy budget, because a venue publishing exact winning quotes
leaks the policy through repetition. Nothing in the auditable-MPC line addresses
what the output *reveals*; it addresses whether the output is *right*. Both are
needed, and together they create a problem neither has alone: the audited value
and the published value are not the same value. **The noise being provably drawn
is not finished** --- section 8.

**2.6a What is not noised, and why that is a decision.** The count of settled
trades over a range of blocks is **not** put behind the budget, because it is
already exact and public. The adversary these results are stated against "sees
what a settlement layer publishes", and settlement is one on-chain instruction
per trade at 18.2M--65.7M gas, so anyone running a node counts them without a
wallet-to-entity map. The AUC 0.500 result protects *attribution* of a
settlement to an entity, which needs a map of coverage rho; it has never been a
claim about the count. Selling a noised version would protect nothing --- the
asker differences it against the chain --- and would hand an honest asker a
worse answer than the free one.

What is secret is the **request** count. A request that settles nothing leaves
no on-chain trace, which is exactly what the unsettled-request attack falling to
0.500 means, so the venue holds that figure alone. It is also the one a maker
cannot get any other way: makers never receive the request, so a maker knows the
numerator of its hit rate and can never know the denominator.

The query built on that is `BlockRangeQuery` --- how many *distinct entities*
asked between two block heights. Distinct entities rather than request events,
because an entity contributes 0 or 1 however wide the range, so the sensitivity
is 1 at every width where an event count's is `cap x windows` and grows as the
asker widens the question. Measured on 150,000 UniswapX fills with real swapper
addresses, the public fill count explains R^2 0.95--0.97 of it, and the residual
--- which is what the epsilon actually buys --- runs 1.69 to 148.98 entities
against a noise of 1.36, so 1.2x the noise at 100 blocks and 4.7x by 600. That
residual is flow concentration: the same 500 fills from 500 takers and from 20
takers are different venues, the chain cannot separate them, and it is the
separation a maker pricing adverse selection wants. **Activity is free;
concentration is what is for sale.**

Two limits belong with it. The simulator cannot evaluate this at all --- it
assigns entities round robin, so the count saturates in one window and the
saturation is a property of the assignment, the same way section 14's band count
was a property of the instrument. And UniswapX records fills, so the population
measured is settled requests; QOMM's denominator includes requests that settled
nothing, and no chain records those. Nothing available measures whether they
come from the same population.

---

## 3. Baldimtsi, Kiayias, Zacharias, Zhang (ASIACRYPT 2020) --- separate input parties, weaker guarantee

Found through 2026/337's related work, and on the *structural* axis the nearest
work of the five: the client-server model, clients providing input and servers
computing obliviously, which is the maker-and-node shape exactly. Their
motivating list even includes order-book matching.

**And they go further than we do on the threat.** End-to-end verifiable MPC
withstands all servers subverted, the CRS subverted, **and the input-providing
users' own client devices subverted**, with human users modelled as having only
logarithmic min-entropy --- they cannot check a device's work and cannot produce
good randomness. The new primitive that gets them there is *crowd verifiable
zero knowledge*, where a set of verifiers each contributes a few random bits and
most of them may be corrupt.

**The price is that correctness stops being exact, and they prove it has to.**

> at the high level of adversity that VMPC is meant to withstand, it is
> infeasible to ensure perfect correctness

The functionality instead enforces a **spreading relation**: if the inputs move
by at most `δ`, the reported output must be *related* to the true one. Their
theorem says nothing more refined than a spreading relation is achievable for
symmetric `f`. The applications that work are the Lipschitz ones --- an e-voting
tally where one attacked voter moves the count by one, an average over `n` users
where one input moves the mean by `(b-a)/n`.

**An argmin over prices is the opposite of Lipschitz.** One corrupted input can
become the winner and set the output price by an unbounded amount, so the only
spreading relation available is the trivial one. *(Their theorem is stated for
symmetric `f` and the key function here is deliberately asymmetric --- ties break
on the maker index --- so the theorem does not literally apply. The mechanism it
describes does.)*

**But the threat it is defending against does not exist here, and that is the
real difference.** VMPC exists because a human voter cannot check their
smartphone, so the device is a threat and the human's intent is the ground
truth. **A market maker is a firm with a machine, and the committed policy *is*
the ground truth** --- the firm is bound by what it signed. If a maker's own
system commits to a bad policy, the audit still holds: it says the maker
committed that policy, and the maker owns the consequence. **The human-device
gap that VMPC exists to close is not present in this setting**, which is why
exact correctness is available here and is not available to them.

Other differences: subexponential assumptions (super-polynomial simulation,
complexity leveraging), `O(λ(n+k)|C|)` cost, and **no implementation** --- it is
a feasibility and infeasibility paper.

---

## 4. Rivinius, Reisert, Rausch, Küsters (IEEE S&P 2022) --- the nearest on threshold, and the strongest argument against our choice

Also found through 2026/337, and on the *regime* axis the nearest of the five.
Threshold secret sharing with parameter `t`, so up to `n - t` malicious parties
still leave enough shares to continue; benchmarks at `n = 3, t = 2`. Publicly
verifiable **and accountable** --- anyone can name the party that cheated ---
**and robust up to the threshold, with no restart**. Lattice (BDLOP)
commitments, so post-quantum. Input parties are separate from compute parties
and may be corrupt.

They also arrive independently at this repository's argument for who the nodes
should be:

> in situations where one expects only a very small number of parties to try to
> abort the protocol (due to the deterrence factor of accountability coupled
> with strong contractual or financial incentives), one generally would choose a
> large threshold

which is `BINDING.md` section 0 --- seven KYB'd entities with a bond to slash are
held by attribution, so prevention buys them little.

**And they have the measurement everybody else in this line lacks.** Against
plain SPDZ on the same neural network, `n = 3`, `t = 2`, `log p = 128`:

| | online communication | overhead vs SPDZ |
|---|---:|---|
| SPDZ | 3.61 MiB | --- |
| Cunningham et al. | 14.21 MiB | |
| **theirs** | **17.48 MiB** | **20x at 0 ms, 11x at 100 ms** |

### Their appendix H argues against exactly what this stack does

Two arguments, and the second one lands.

**One: the plaintext space has to grow with the commitment's security.** In a
SPDZ-like protocol with BGV preprocessing, widening `p` to hold a DLOG group
order widens the BGV parameters with it, and they tabulate the damage. Their
conclusion is that Pedersen is not affordable and lattice commitments are.

**This stack measured 2.00x for the same widening, and both numbers are
right.** There is no somewhat-homomorphic encryption here at all --- honest
majority with Shamir has no lattice preprocessing whose plaintext modulus could
blow up. The 2.00x is the wire format and nothing else. **Their argument is
sound about their protocol and does not transfer to this regime, and that is
worth stating in both directions**: it also means our 2.00x is not evidence that
matching the field is cheap for anyone else.

**Two: computational binding decays over the life of a commitment.** A party
holding a share `[r]_i` and its commitment, who can eventually break the
discrete log, can produce a decommitment to `[r]_i - c` and shift another
party's input by `c` undetectably. Their own words: *"In an auction, this could
be used to reduce other parties' bids and increase the chances of winning."*

**That is this stack's exact shape.** A maker's policy commitment is not opened
once and discarded --- it sits for the life of the policy and is opened against
every quote, and the mechanism is an auction. **This is the strongest argument
in the literature for the post-quantum direction specifically here**, and it is
better than the generic one: it does not need a quantum computer, only enough
time. It is recorded in `BINDING.md` section 6 rather than left in a paper.

**What they have that this does not: accountability and robustness.** Their
judge names the cheating party and the protocol does not restart. The quote
proof shows the winner was correct; it does not say who broke it if it was not,
and `roles.py` attributes only what was dealt. That is a real gap and their 11x
to 20x is what closing it costs in their regime.

---

## 5. Prime Match (Polychroniadou et al., USENIX Security 2023) --- the closest thing running

In production at J.P. Morgan, and by their own description the first secure
multiparty computation running live in traditional finance. The motivation is
nearly identical: clients must hand the bank their direction and size, and if
that leaks the price moves against them before they trade.

**5.1 There is a semi-honest party, and here there is not.** Prime Match is
secure against *malicious clients and a semi-honest bank*. The bank is the hub
of a star topology --- clients deliberately do not talk to each other, because
they do not want to reveal their identities --- and it is trusted not to deviate.
That is a defensible choice for a bank matching its own clients. It is not
available to a venue whose premise is that the venue cannot be trusted with the
order flow. **Here there is no semi-honest party.**

**5.2 The computation is a different size.** Theirs is a two-party minimum
between two quantities, invoked `n^2` times. Ours is a seven-party tournament
over `M` makers' committed policies with range checks, freshness checks and an
inventory carry. Their throughput is about **10 symbols per second**, running
**every 30 minutes** in production. A quote here is 3.621 s at 15 ms RTT and
23.0 s intercontinental at `M = 16` over four assets. **The units are not the
same unit and the ratio should not be reduced to one number** --- but on any
reading, **nothing here is faster than Prime Match**, and that goes first.

**5.3 The outcome is not auditable by a third party.** Nothing in Prime Match
produces an object a regulator who was not present can check. Privacy is the
goal and it is achieved; provable best execution is not attempted. That is the
axis this repository is on, and the reason the comparison is not simply "they
are faster".

**5.4 What they have that should be read next.** A **two-round secure linear
comparison protocol with no preprocessing and malicious security**. The
tournament here is comparisons, and comparison width is what the whole field
argument turns on. Whether a two-party construction transfers to seven-party
Shamir is not obvious and is not answered here.

---

## 6. Baum and Zok (`eprint 2026/337`, February 2026) --- the newest, and it takes the idea

Six months old, and it does deliberately what `BINDING.md` section 4.6 set out
to try: replace 2014's Pedersen commitments with publicly verifiable commitments
from VOLE-in-the-Head, so auditability rests on a random oracle and nothing else.
UC-secure, post-quantum, OLE preprocessing instead of lattice SHE.

**So the cryptographic idea is taken and should not be claimed here.** What is
left is a division of labour:

| | 2026/337 | here |
|---|---|---|
| VOLEitH commitments for auditable MPC | **the contribution** | not claimed |
| security proof | UC, 68 pages | none |
| input vs computing parties | **not separated** (stated in the paper) | separated |
| binary circuits | open problem (their appendix A) | not needed |
| implementation | **none** | `zk/voleith.py` |
| efficiency | asymptotic estimate, `O(n·λ²·|C|)` online | measured |

**They report no benchmarks.** Appendix C is an estimate --- "we estimate the
communication complexity" --- 5 offline rounds, `4 + D` online, and an online
term they note could "trivially be lowered" with GGM trees, without doing it.

What is here instead, on `host-a`, `n = 30`, over 167 committed values, both
arms proving the same public linear statement and both publicly verifiable:

| | prove | verify | proof |
|---|---:|---:|---:|
| Pedersen (ed25519) | 18.64 ms | 15.48 ms | 5,440 B |
| VOLE-in-the-Head | 73.06 ms | 69.94 ms | 45,616 B |

and the finding that only shows up once it exists: **88% of that proof is the
VOLE consistency corrections** and the tree openings are 4%. Over `F_2` --- FAEST's
setting, and the setting of every published number for this construction --- those
corrections are bits. Over a 127-bit prime they are 16-byte elements. **The
published "2x the designated-verifier communication" does not carry to a witness
that is not bits**, and neither does the computation: 17.8 MB of PRG output
against FAEST's 819 kB at identical tree parameters.

That is not a refutation --- their asymptotic has the `λ²` in it, and this is
what `λ²` looks like at `λ = 128` over a wide field. It is the number their paper
does not contain.

**And one property of theirs matters more than it reads.** Their commitments are
*one-time* linearly homomorphic: `Delta` is public after the first opening, so a
second statement about the same commitment is bound by nothing, and they buy a
second opening with a random-oracle commitment to the opening. **A maker's
policy commitment here is opened against every quote for the life of the
policy.** That is a redesign, not a footnote. `voleith.Prover.prove` raises
rather than allowing it.

---

## 7. The settlement leg, which none of the five has

Publicly auditable MPC ends when the output is opened. **A quote that is opened
and then settled in the clear has leaked everything the computation protected**:
the asset, the size, the counterparties and, by difference, the policy. The
audit trail is intact and the privacy is gone.

**zkPI** (`zk/zkpi.py`) makes the payment instruction itself a commitment plus a
proof. A settlement venue checks an instruction is well-formed, authorised and
unspent, and learns none of the asset, the amount, the price, or which entity
holds it --- only that *some* enrolled entity holds an instruction whose asset
and amount lie in declared ranges, whose price matches the quote the nodes'
quorum signed, whose deadline has not passed and whose nullifier is unseen.

**DeFMI** (`DEFMI.md`) is the ledger. Homomorphic balances so value is neither
created nor destroyed by the group operation alone; a range proof so no balance
goes negative; a product proof for cash = quantity x price; an equality proof
across generators so the securities leg is the instructed quantity; a nullifier
so an instruction settles once. **48.8 ms to settle at a 40-bit balance width,
29,523 bytes on the wire**, of which about 53% is the instruction. Linear in the
balance width and nothing else: 0.55 ms and 448 bytes per bit.

**Standard: every gadget.** Pedersen, Bulletproofs, Groth–Kohlweiss one-of-many,
Zcash-style nullifiers, FROST, confidential-transaction balance arithmetic. Each
has a paper and none of those papers is this one.

**Not standard: that the settlement leg is bound to the audited computation.**
The price commitment the quote proof shows is minimal is *the same commitment*
the quorum signs, is *the same commitment* the instruction carries, is *the same
commitment* the ledger's product proof consumes. **One value, four proofs, never
opened.** That chain is the composition being claimed, and it is why "the gadgets
are standard" is accurate rather than damaging.

The nearest published thing is delivery-versus-payment on DLT, which assumes the
price is public. Prime Match does not settle at all --- a match goes back to the
bank's existing pipeline.

---

## 8. What is not finished

- **A threat model and proofs, but no UC treatment.** `security.tex` states the
  setting and proves soundness of the input check, that naming is sound and never
  names an honest party, unique naming from the Reed--Solomon distance, and
  statistical hiding of the opening. What is *not* proved: the underlying MPC
  protocol (assumed and cited), and composition, which is argued rather than
  shown. Writing those proofs is what found the flaw in the next bullet.
- **Accountability, partly closed since this was written.** The engine now names
  the party that sent a malformed share (`locate-inconsistent-shares.patch`,
  1.33x traffic, rounds unchanged), and the per-party input check names the node
  that fed a value other than the one it was dealt --- in the circuit, for **one
  extra round and 0.39% more traffic** than merely detecting one, at soundness
  `2^-245`. An earlier version of that check derived its coefficients from the
  dealer's commitments, which a node reads before it feeds the engine; writing
  the proof found that a node could then choose an error in their kernel and pass
  with probability 1. The challenge is now drawn after the input phase. A verdict
  is still not a repair: both name, neither prevents.
  `ACCOUNTABILITY.md` has the five rungs and where each mechanism sits.
- **Robustness, built.** `T = 2` of 7 is `t < n/3`, and the useful line turns
  out to be `n >= 4T+1` --- the point at which a degree-`2T` product is directly
  correctable, so a decoder replaces GSZ's segmenting, checkpoints and player
  elimination entirely. Two of the three things that would have had to be
  written are already in MP-SPDZ, in ATLAS rather than in Shamir: the rotating
  king and the random double sharings. Removing the king --- the one place a
  consistent sharing of the wrong value can be introduced --- and having every
  party decode the masked product for itself gives, measured at `n = 9`:
  **the correct answer with the culprits named, under one and two liars, without
  stopping**, at 18.222 elements per party per multiplication against the 64.236
  the deployed engine spends, with fewer rounds
  (`robust-atlas.patch`, `artifacts/robust_atlas.json`). What is not robust is
  the preprocessing, which is allowed to abort because it consumes no inputs.
  What it costs is two more institutions, which is the risk this register says
  matters most.
- **The differential-privacy noise is generated outside the MPC**, so the
  published quote is noised but not *provably* noised.
- **Selective disclosure is unimplemented.** The design says which fields a
  supervisor can open; the code does not do it.
- **There has never been a seven-site deployment.** Cross-region figures come
  from a delay proxy on one machine, which reproduces round trips and not
  jitter, loss or clock skew.
- **The staleness measurement has selection bias.** UniswapX fills are the trades
  that happened; the ones that did not are the interesting ones.
- **The VOLE-in-the-Head arm is one linear statement**, not the MPC protocol of
  2026/337, and the linear-code instantiation is arithmetic in `run_voleith.py`
  rather than code. It also shrinks the proof 2.4x and not fourfold: a general
  code is homomorphic only across blocks, so an inner product with a distinct
  coefficient per value needs the paper's degree-2 protocol and its 2x
  overhead. The fourfold figure counted the code swap and not the protocol.
- **Two of the five were found through a third paper's related-work section**,
  not through a search of our own. That has now happened twice in this project.

---

## 9. What would make this a cryptography paper

Nothing above is a cryptographic result. Four questions are, and they are ranked
by whether anybody has an answer rather than by how interesting they sound.

### 9.1 A publicly verifiable linearly homomorphic commitment over `F_p` that opens more than once

**This is the sharpest of the four and it is the one this repository's own
measurements point at.**

VOLE-in-the-Head commitments are **one-time**: `Delta` becomes public at the
first opening and binding is gone. Baum and Zok formalise this and buy a second
opening by committing to the opening in the random oracle, which works when the
openings can be queued *before* `Delta` is revealed.

**An RFQ cannot queue them.** The coefficients of each quote's check are derived
from the request, and the request has not arrived yet. So a maker's policy would
need a fresh commitment per quote --- and **that destroys the property the
commitment existed for**, because a maker free to re-commit each time is free to
quote a different policy each time.

The escape that exists is lattice: BDLOP commitments are ordinary computationally
binding commitments and reopen freely, which is why Rivinius et al. chose them.
So the design space today is:

| | assumption | openings | size |
|---|---|---|---|
| Pedersen | discrete log | many | 32 B, smallest |
| BDLOP lattice | SIS | many | kilobytes |
| VOLE-in-the-Head | **random oracle only** | **one** | 2,672 B commitment, 45,616 B proof (measured) |

**The open question is the missing row: random-oracle-only, many openings.**
That is a primitive question, it has an application that forces it, and it is not
answered by anything read here.

### 9.2 Comparison without slack, in a field that also has to hold a group order

The tournament is comparisons; comparisons over a prime field need bit
decomposition or slack; slack forces the field wider; a wider field costs traffic
on every quote forever. **Rabbit** (FC 2021) removes the slack using the
commutativity of addition over rings. **Prime Match** gets a two-round malicious
comparison with no preprocessing at all. Neither is stated for seven-party Shamir
with a commitment scheme that has to agree with the field, and whether Prime
Match's two-party construction survives the move is not obvious.

### 9.3 Public accountability in an honest majority, priced

Rivinius et al. measured it in a dishonest majority: 11x to 20x. **The
honest-majority number does not appear to exist.** And there is a specific reason
to think it is much smaller here: the commitment machinery that makes the output
publicly verifiable is already deployed, and the malicious check is a linear
statement over committed shares, so the auditor who can replay the computation
may be able to replay the check and see whose contribution does not match.
**That is a hypothesis, not a result**, and what would falsify it is the check
turning out not to expose per-party contributions.

### 9.4 Robust reconstruction: built, run, and reproduced

`ACCOUNTABILITY.md` section 3.6: at `n = 7`, `t = 2` the shares are `RS[7,3]`
with distance 5, so Berlekamp--Welch corrects `T = 2` errors and names the
senders, locally. The costs are collecting `n` shares instead of `2t+1` (40% more
opening traffic) and the fact that unreduced products are `RS[7,5]` and correct
only one error.

**It was the cheapest thing on this page and it is now done.** The operative
line turned out to be `n >= 4t+1` rather than `t < n/3`, which makes a decoder
sufficient and the segmenting, checkpoints and player elimination unnecessary.
At nine nodes and threshold two the protocol corrects two wrong shares of a
masked product, names who sent them and does not stop; three refuses past the
capacity, and seven refuses to start rather than pretending. Measured on two
machines with two independent builds
(`artifacts/robust_atlas.json`, `robust_atlas_host_c.json`), and the decoder is
in Rust as `qomm-zk/src/shamir.rs` beside the commitments, because the binding
chain now deals over the same field.

What is *not* robust is stated in the same place: the double sharings, the
output opening and the input phase. The input phase is the one that matters ---
inputs are the sum of every node's share, so one missing node destroys the
value and no decoding helps.
