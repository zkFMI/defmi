<!-- BEGIN GENERATED WIRE SPEC -->
# zkPI on the wire, version 2

Big-endian throughout. Every field is fixed-width or length-prefixed, and the order below is the order on the wire. Nothing is optional: an instruction with a field missing is not a shorter instruction.

| field | bytes | what |
| --- | ---: | --- |
| magic | 8 | `QOMMZKPI` |
| version | 2 | currently 2. A verifier that meets one it does not know **stops** --- it does not guess at a layout, because a misparsed commitment is a valid point |
| amount commitment | 32 | compressed Ristretto |
| price commitment | 32 | compressed Ristretto |
| asset commitment | 32 | compressed Ristretto |
| payer handle | 32 | compressed Ristretto |
| payee handle | 32 | compressed Ristretto |
| deadline | 8 | seconds since the Unix epoch |
| nonce | 32 | what makes the nullifier unique |
| quote proof digest | 32 | SHA-256 digest of the complete public quote proof; it reveals neither the packed winner nor the price |
| signature | 64 | FROST over Ristretto255 |
| amount proof length | 4 |  |
| amount range proof | that many | jointly assembled threshold range proof |
| price proof length | 4 |  |
| price range proof | that many | jointly assembled threshold range proof |

## Version 1 compatibility format

Version 1 is still decoded and re-encoded when explicitly tagged as version 1. It carries an 8-byte packed quote key, a range-commitment count, the corresponding commitments, and two Bulletproofs. It is a migration format, not the product issuance path. Version 2 emits a 32-byte quote-proof digest and two jointly assembled threshold range proofs.

## What is deliberately absent

No compression, no self-describing container, no forward compatibility. Each is a way for two implementations to disagree about what they read, and the table above is a day's work to implement from.
<!-- END GENERATED WIRE SPEC -->

## Checking an implementation against this

Vectors are in `artifacts/zkpi_vectors/`. The directory contains one accepted
instruction for each supported wire version and five damaged forms of each.
`accepted-v2.bin` is the product shape: its two range proofs were assembled from
node-local Shamir contributions and its signed quote binding is a 32-byte proof
digest. The current fixed product vector is 9,726 bytes at 16-bit quantity and
32-bit price bounds; the unsuffixed files retain the 1,572-byte version-1
compatibility vectors. These sizes make the migration cost explicit rather than
presenting the smaller legacy wire as the product cost.

```
qomm-zkpi-verify --check-vectors artifacts/zkpi_vectors
```

The accepted vector must **decode and re-encode to the same bytes**. That is a
stronger statement than "it parsed": an implementation that dropped a field and
re-derived it would pass the second and fail the first, and it is the first that
decides whether two venues settle the same instruction.

Checking cannot compare against a freshly issued instruction --- a fresh one has
fresh randomness --- so the artefact on disk is the fixed point rather than the
generator. `--vectors <dir>` regenerates it, which is a thing to do when the
format changes and never because a check disagreed.

## Running the verifier

```
qomm-zkpi-verify --self-test                       # issue v2, encode, decode, verify
qomm-zkpi-verify --quorum <hex> --now <seconds> < instruction.bin
qomm-zkpi-verify < instruction.bin                 # layout only, and it says so
```

Exit 0 accepts, 1 rejects, 2 could not be asked. Without a quorum key it checks
the layout and says that is a parse and not a verification, because a tool that
printed "ok" for a well-formed unsigned instruction would be worse than none.

## Where this runs now

The implementation target is a dedicated **non-EVM Avalanche L1** in
`avalanche/defmivm/`. Avalanche consensus orders native asset-registration,
account-opening and multi-leg settlement transitions. No Solidity, EVM bytecode
or Subnet-EVM precompile is in the acceptance path.

The trust boundary is explicit. The DeFMI node committee verifies the two
jointly assembled threshold range proofs and the complete quote proof before
signing. The product transaction carries the complete submitted evidence, and
every custom-VM validator independently checks the 3-of-7 Ed25519 approval,
typed zkPI, complete quote proof, joint ranges, taker price limit, asset link,
DvP relation, chain and rail domains, deadline, sequence, previous state root
and nullifier before applying the transition atomically. Validators do not
re-run the private MP-SPDZ transcript or prove the node-local share-to-proof
handoff; that remains the committee trust and liveness boundary.

`artifacts/avalanche_qomm_full_acceptance.json` records the full local path: five
AvalancheGo validators, seven process-isolated MP-SPDZ parties, an atomic batch
of two RFQs at height 53, a later claim materialisation at height 54 and a
validator restart with identical state roots. It is evidence for native
execution and recovery on one host, not for independent organisations, a real
WAN or public-network readiness.

## Historical execution-layer comparison

Before the dedicated VM and version-2 product instruction existed, the project
measured where the version-1 compatibility verifier could fit. Its verification
is about 1.6 ms of curve arithmetic, dominated by two Bulletproofs. The retired
chain-comparison runner measured one ed25519 scalar multiplication
implemented in EVM bytecode at 302,401 gas. These measurements explain why EVM
bytecode was rejected; they are not the deployed path.

### Two earlier candidates, and how they differed

**Avalanche, earlier design.** Subnet-EVM takes stateful precompiles as build-time
configuration, so the verifier is Go that you write, at an address you choose,
priced at a gas cost you set. Nothing here is a ceiling: the block limit and the
gas schedule are both yours. The cost is that they are yours --- the curve code
is code this project would write and maintain, and a bug in it is a consensus
bug on a chain nobody else is watching.

**Solana.** The fit looks closer than it is, and the way it fails is the
interesting part. Programs are Rust compiled to SBF, and this stack is already
Rust. The runtime carries **ristretto255 syscalls** --- point validation,
addition, subtraction, scalar multiplication and multi-scalar multiplication ---
which is the exact curve every commitment, every ring proof and every FROST
signature here is built on. That code is Solana's, maintained and deployed
already, so there is no precompile to write and none to get wrong.

Their published schedule makes the curve half exact rather than guessed: a
multi-scalar multiplication is `2,303 + 788(n-1)` units, so the 137-term one a
crowd of 128 needs is 109,471, and a transaction may ask for 1,400,000.

**The other half is not on any table, so it was measured.** `solana/` builds an
SBF program that runs each piece on its own and reads the units off a
transaction. Compute units are counted by the virtual machine rather than
timed, so the figures are reproducible to the unit on any host and carry no
host label --- what they carry is the toolchain, because a unit count is a
property of the compiled program. Agave 4.2.1, `cargo-build-sbf` 4.1.0,
`artifacts/solana_cu.json`.

| operation | compute units |
|---|---:|
| scalar field: one multiplication | **5,450** |
| scalar field: one addition | 350 |
| Merlin transcript, per 32-byte item | 3,688 |
| the same through the `sha256` syscall | **132** |
| one base-point scalar mul **in the program** | ~863,000 |
| one ristretto scalar mul **as a syscall** (published) | 2,208 |

Three things fall out, and the first one settles the question.

**The bottleneck is the field, not the curve, and Solana has no syscall for the
field.** A Groth--Kohlweiss verifier evaluates one degree-`log2(n)` polynomial
per commitment before it touches a point at all, which is `n log2(n)`
multiplications in the scalar field. Measured directly: a crowd of 16 costs
398,825 units and a crowd of 32 costs 951,503, and 64 and 128 exceed the
ceiling and cannot be run. The arithmetic that predicts those two also predicts
the ones that will not run --- `896 x 5,450` plus the subtractions is about
**5.2 million units for a crowd of 128, against a ceiling of 1.4 million.**

So Solana's advantage does not reach the problem. The syscalls cover exactly the
operations that were never the constraint.

**Doing curve work in the program instead is 391x worse than asking the
runtime.** One base-point scalar multiplication in dalek costs about 863,000
units --- 62% of an entire transaction --- against 2,208 for the syscall. That
is not a criticism of dalek; it is what metering field arithmetic per
instruction costs, and it is the same reason the polynomial evaluation is
expensive.

**Merlin should go.** STROBE over Keccak has no syscall shaped for it and costs
3,688 units per 32-byte item absorbed, so binding a crowd of 128 to a proof is
487,739 units on transcript alone. The `sha256` syscall does the same
absorption for 132 units an item --- **28x cheaper**, 17,062 for the same 128.
That is a portable change and worth making whether or not this ever runs on
Solana.

### What actually fits

| crowd | polynomial | msm syscall | sha256 transcript | total | of a transaction |
|---:|---:|---:|---:|---:|---:|
| 16 | 398,825 | ~18,000 | 2,278 | ~419,000 | 30% |
| 32 | 951,503 | ~30,700 | 4,390 | ~987,000 | 71% |
| 64 | ~2.1M* | ~53,000 | 8,614 | ~2.2M* | **over** |
| 128 | ~5.2M* | 108,683 | 17,062 | ~5.3M* | **over** |

\* These two exceed the ceiling and could not be run. The figures are
arithmetic on the measured per-operation costs, and the rows that did run --- 16
and 32 --- are what the arithmetic reproduces.

A crowd of 32 fits and leaves 29% of the transaction for everything else, and a
settlement also carries two Bulletproofs range proofs, which are heavier than
any line above. A crowd of 128 --- the size the off-chain measurement says is
affordable, at 3.84 ms --- is not close.

**Three predictions, written before the run, and two of them were wrong in the
direction that mattered.** A scalar multiplication was predicted at 500 to
1,000 units and costs 5,450. From that, the scalar half of a crowd-128 check
was predicted at 400,000 to 800,000 units and "inside the ceiling, but not by
much"; it is about 5.2 million and three and a half times over. The transcript
prediction was right in direction and low in magnitude on both arms. **The
useful conclusion is the one the arithmetic could not reach: a verifier whose
cost is field arithmetic does not belong inside a metered VM**, and that is a
statement about the shape of the computation rather than about Solana.

### Arbitrum Stylus, measured the same way

Stylus deploys Rust compiled to WASM alongside EVM contracts, meters it in ink
at ten thousand to the gas, and takes `curve25519-dalek` without modification.
The same workloads were run there --- a Nitro dev node, `cargo stylus` 0.10.9,
each workload a real transaction with a real receipt --- so the two chains can
be read line against line. `artifacts/stylus_gas.json`.

| operation | Solana | Stylus |
|---|---:|---:|
| scalar multiplication | 5,450 CU | **299 gas** |
| scalar addition | 350 CU | 238 gas |
| transcript, per item, in software | 3,688 CU (Merlin) | 150 gas (sha256) |
| transcript, per item, host primitive | 132 CU (`sha256`) | 39 gas (`keccak`) |
| base-point scalar mul, in the program | ~863,000 CU | 64,635 gas |
| multi-scalar mul, 137 terms | 109,471 CU (**syscall**) | 3,649,058 gas (**software**) |

The verifier's own final combination is $N + \log_2 N + 1 = 136$ terms at a
crowd of 128, which Solana prices at 108,683; the row above is the measured
137-term one, a single term wider.

**The two chains fail at opposite ends, and neither has both halves.** Solana
carries the curve and meters the field dearly: the polynomial evaluation alone
is about 5.2 million units against a 1.4 million ceiling, and the cheap
multi-scalar syscall cannot rescue it. Stylus meters everything cheaply --- a
scalar multiplication is eighteen times less of its budget --- and offers no
curve primitive at all, so the multi-scalar multiplication is done in software
and becomes the whole cost.

| crowd 128 | polynomial | multi-scalar | transcript | total | fits |
|---|---:|---:|---:|---:|---|
| Solana | ~5.2M CU | 109,471 | 17,062 | ~5.3M CU | **no**, ceiling 1.4M |
| Stylus | 390,723 | 3,649,058 | 7,882 | **4,047,663 gas** | yes, 12.6% of a 32M block |
| a precompile | native | native | native | 3.84 ms | priced by the venue |

On Stylus the missing curve primitive costs **9.2x everything else the check
does**: 3,649,058 against 398,605 for the polynomial and the transcript
together. Priced the way Solana prices it the whole check would be 508,076.

### "It fits" is true of the component and false of the deployment

The line above says a crowd of 128 takes 12.6% of a block and fits, and read on
its own that is misleading. It is one component. A settlement also verifies the
instruction, and the instruction carries two range proofs.

The multi-scalar cost is linear in its terms and the measured slope is
**26,318 gas a term** (464,905 at 16 terms, 6,785,432 at 256, and the three
gaps between them agree to 0.2%). A 32-bit range proof verifies as one
multi-scalar multiplication of about $2n + 2\log_2 n + 6 \approx 80$ terms ---
that count is structural arithmetic laid on a measured slope, not a measurement
of a range proof --- so each is about **2.1M gas** and a settlement carrying two
of them is:

| | gas |
|---|---:|
| vetting check, crowd 128 | 4,047,663 |
| two range proofs | ~4,210,000 |
| **one settlement** | **~8.3M** |

Which is **26% of a 32-megagas block**, and against Arbitrum's sustained
throughput of a few megagas a second it is **fewer than one settlement per
second using the entire chain**. In money it is nothing --- about \$0.29 at the
0.01 gwei floor --- so the objection is not the fee. It is that a settlement
would consume a quarter of a public chain's block, and no venue gets to do that
at volume, or wants to bid against itself for the privilege.

**So Stylus shows the check is possible inside a metered VM and not that it is
a deployment.** The same work is 3.84 ms of native code, and a precompile
running native code puts settlements per second where an L2 puts settlements
per second per chain. That is not a small difference in cost; it is a different
order of system.

The measurement is still worth having, and for two reasons. It withdrew a
sentence that was too strong, and it produced the number that makes the
precompile conclusion quantitative rather than preferred: **a factor of about
three orders of magnitude in throughput**, from the same code.

**The prediction held and one sentence has to be withdrawn.** Stylus was
predicted to fit a crowd of 128 in one to ten million gas and it takes 4.05
million. But the Solana section above concluded that *a verifier whose cost is
field arithmetic does not belong inside a metered VM*, and that is now too
strong. It belongs inside a VM metered as cheaply as this one. The accurate
statement is about the **price of an instruction** rather than about metering,
and the sharper finding is the one the second measurement produced rather than
the first: **what a chain must have is not one of the two halves but both** ---
a cheap instruction and a curve primitive --- and of the three options only a
precompile has both, because native code needs neither.

(One prediction was untestable as posed. It said the WASM instruction count per
scalar multiplication would be within 3x of SBF's. Both runs report prices, not
instruction counts, in units that do not convert, so nothing here confirms or
refutes it. A prediction naming a quantity the experiment does not produce is a
badly written prediction, and is recorded as one.)

### Which reverses the expected answer

Solana looked like the better fit --- same curve, same language, syscalls
already deployed --- and it is the one option that will not run the check at
all. Stylus ran the measured component at 4.05 million gas, while the earlier
Avalanche design would have used native precompile code. The final implementation
instead uses the dedicated custom VM and the committee-verification boundary
described above.

A precompile does not avoid the work. It avoids **metering the work per
instruction**, and it avoids **doing curve arithmetic in a language the runtime
has no primitive for**, and between them those are the whole of the difference.
Stylus is the second-best answer and a real one: it keeps Ethereum's security
and its liquidity, and pays 7.2x for the curve primitive it lacks.

**The choice of chain is still not only about compute.** Avalanche lets
you pick the validators; Solana does not. This project's governance argument ---
seven vetted entities with a bond to slash --- is an argument about who runs the
machines, and a permissionless validator set is a different answer to that
question, not a cheaper one. Whether market infrastructure can settle on a chain
whose operators it did not choose is a question for the venue's regulator, and
it is the one that should decide this. What the measurement settles is narrower
and worth having: if the check is to run on chain at all, it runs as native
code or it does not run.
