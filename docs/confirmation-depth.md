# Confirmation depth for a DigiByte anchor — derivation method (draft, 2026-10-06)

**Status: method and first measurements. No depth is adopted by this document.** The crew
rules on the method first; the number follows from the method, not the other way round.

## Why a derivation is required

`draft-fassbender-scitt-time-anchor-07` (2026-09-24) says a profile for another ledger must
supply, among four things, "a confirmation-depth requirement derived from that ledger's own
work rate, since the value used here is not portable and carrying it over unchanged would be
an error rather than a simplification", and evidence that the ledger qualifies, "with the first
[property] stated in terms of the cost of rewriting that ledger's own history". The draft prices
its Bitcoin depth against the cost of producing six Bitcoin blocks.

This calendar currently labels receipts `final` at **100 confirmations**. That number came from
DigiByte Core's coinbase maturity, which is a wallet-safety constant, not a rewrite-cost
figure. It is therefore exactly the carried-over value the draft warns against, and it is
replaced here by a method.

## What "rewriting history" means on DigiByte

A verifier of a DigiByte-anchored receipt trusts that the block containing the anchor stays in
the best-work chain. An attacker who wants to make a receipt false must produce an alternative
chain, from a point before the anchor block, with more cumulative work than the honest chain
accumulated in the same span, and do it before the receipt's consumer stops caring.

Three DigiByte facts shape the cost, all read from Core v9.26.6 source:

1. **Five proof-of-work algorithms, round-robin by difficulty.** Blocks carry the algorithm in
   version bits 8 to 11 (`src/primitives/block.h`: Scrypt 0, SHA256d 2, Groestl 4 inactive,
   Skein 6, Qubit 8, Odocrypt 14). Over 2,000 recent mainnet blocks each active algorithm
   produced between 387 and 415 blocks, one fifth each.
2. **A block's work is a geometric mean across all active algorithms, not its own
   algorithm's work.** `GetBlockProofImpl` (`src/chain.cpp`, from block 1,430,000) computes
   each block's proof as a function of the current targets of every active algorithm. So an
   attacker gets no chainwork credit for being strong in one algorithm: every block they add
   is credited as if it carried the network's average, and they must produce more *blocks*
   than the honest chain over the span, in the algorithm mix the difficulty rules enforce.
3. **Per-algorithm difficulty retargets every block (MultiShield, `GetNextWorkRequiredV4`,
   `src/pow.cpp`)** over a 10-block-per-algorithm averaging window, with a target spacing of
   75 seconds per algorithm (five algorithms, 15-second blocks). An attacker mining one
   algorithm faster than its 75-second spacing drives that algorithm's difficulty up on their
   own chain within a few blocks. Outpacing the honest chain therefore requires a majority of
   work across the algorithm mix, not in one of them.

Consequence: the cost to rewrite d DigiByte blocks is bounded below by the cost of producing
more than d blocks' worth of work across all five algorithms within the time the honest chain
takes to produce d blocks, about 15·d seconds. Raw hash counts are not comparable across
algorithms (a Scrypt hash and a SHA256d hash cost different energy), so the cost has to be
priced per algorithm.

## First measurements (2026-10-06, 2,000 blocks ending at 24,336,336)

Work per block by algorithm, in that algorithm's own hashes (target → 2^256 / (target + 1)):

| algorithm | blocks in sample | mean work per block (hashes) |
|---|---:|---:|
| SHA256d | 410 | 2.8 × 10^18 |
| Skein | 387 | 6.1 × 10^16 |
| Qubit | 396 | 2.9 × 10^15 |
| Scrypt | 415 | 8.8 × 10^14 |
| Odocrypt | 392 | 8.6 × 10^14 |

Reference: one Bitcoin block at the current difficulty is 5.7 × 10^23 SHA256d hashes; the
draft's six-block Bitcoin depth is 3.4 × 10^24 hashes. One Bitcoin block carries roughly
200,000 times the SHA256d work of one DigiByte SHA256d block. That comparison is only for
SHA256d; it says nothing about the other four algorithms, and it is not the cost figure.

## The cost model to be filled in (what the crew should rule on)

For a depth d, the attacker must, within about 15·d seconds, produce at least d + 1 blocks
with chainwork exceeding the honest d. Under the rules above, the cheapest way is to hold
roughly a majority of each algorithm's hashrate for that window, or more of some to compensate
for the per-algorithm retarget penalty. The cost is then the sum over algorithms of
(hashrate needed) × (window) × (price per hash-second), where the price is:

- **rentable algorithms** (SHA256d, Scrypt): the public marketplace rate, which gives a hard
  dollar lower bound for a short window;
- **non-rentable algorithms** (Skein, Qubit, Odocrypt): hardware that must be owned; Odocrypt
  in particular changes its hash function on a schedule to resist fixed hardware. No rental
  price exists, so the cost is bounded by the capital cost of the hardware the honest miners
  run, which is a weaker, harder-to-cite number.

Honest statement of the result before any number is filled in: **a DigiByte anchor is cheap to
produce and cheaper to rewrite than a Bitcoin anchor by orders of magnitude.** Its value is
latency (minutes to inclusion against hours on a congested Bitcoin calendar), independence
from the Bitcoin calendars that are currently failing, and a second, uncorrelated witness. A
profile that says otherwise would be wrong. The depth chosen must make a rewrite more
expensive than the plausible value of falsifying a timestamp for the consumers this calendar
expects, and the document must say what that threshold is and how it was priced.

## What is needed to finish

1. Per-algorithm hashrate from the measured targets and spacing (derivable from the sample).
2. A dated price per hash-second for SHA256d and Scrypt from a public rental market, with the
   source cited.
3. A stated assumption for the three non-rentable algorithms, labeled as an assumption.
4. A chosen threshold value (what a falsified receipt could be worth) and the depth d at
   which the computed cost exceeds it, with the sensitivity to the price inputs shown.
5. Crew review of 1 to 4 before the calendar's `POLICY.confirmations` changes.

Until then the calendar's receipts should say what they are: `finalized under the
100-confirmation policy`, with this document linked, and no claim that 100 was derived.
