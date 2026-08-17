# Silent data corruption in blockchain indexing: five times it looked like success, plus three misclassifications

> 中文原文：[silent-data-corruption.md](silent-data-corruption.md)

> This is a record of eight data-corruption incidents encountered while scanning
> 392,258 ERC-8004 registered identities across 12 chains. What they have in common
> is that **failure looked like success** — no error, no interruption; the scan
> "completed" and produced a wrong dataset.
>
> Measured 2026-08-10 through 2026-08-16. Everything here can be re-run and checked
> against the code: <https://github.com/yaojin0609/erc-8004-liveness>
>
> **How these eight bugs relate to the main report's data**: six of them were found
> *after* the 2026-08-10 state snapshot was produced. So the registration and log
> data in the main report is **not** the output of that original scan — each fix was
> followed by a rescan of the affected chains (celo three times, scroll twice, BSC
> and base once each), and the final dataset is the result of a full re-run after all
> fixes. The state snapshot itself (`ownerOf` / `tokenURI`) is anchored to block
> heights at 08-10 and was unaffected. The integrity gate on the final dataset:
> **zero gap on all 12 chains, and the census was not truncated** (see
> "The only defense that holds" below).
>
> In other words: this document is the reason to trust the main report's data,
> not a reason to doubt it.
>
> **On naming names**: specific RPC providers and failure modes are named below.
> This is **a measurement at a point in time**, not a verdict on service quality —
> free public RPC tiers make different tradeoffs by design, and availability changes
> (one endpoint in this document passed the canary test and then returned 500
> continuously during the real scan). The point is to let others avoid the potholes,
> not to accuse anyone.

---

## Why this deserves its own writeup

People who build blockchain indexers usually defend against *errors*: timeouts,
rate limits, dead nodes. Those are easy — retry and rotate.

The dangerous class is different: **upstream returns a syntactically valid,
structurally complete, but incomplete response.** Your code gets HTTP 200 and a
well-formed JSON array. There is no reason to be suspicious. The scan finishes, the
log says `✓ success`, and you take that data and compute metrics, write a report,
publish conclusions.

Five of the eight incidents were this kind. The other three **failed, but the error
was classified wrong** — the system did stop or crash, but the error message pointed
somewhere else entirely, so the fix was aimed in the wrong direction from the start.

### This is not a new failure mode; it is an old failure mode in a new failure domain

Silent Data Corruption has mature literature in hardware and storage. Meta published
a study of SDC at a scale of hundreds of thousands of machines in 2021, in which a
canonical symptom is exactly "rows mysteriously missing from a database"; earlier,
CERN studied data integrity in storage systems in 2007. Both reach the same
conclusion: **at sufficient scale, "compute/storage quietly returns a wrong result"
is the norm rather than the exception, and the only workable countermeasure is
end-to-end integrity verification** — not trusting any single component's success
signal.

What follows is the same failure mode reproduced in **public RPC as a new failure
domain**. The "reconcile using a property of the data itself" gate below is the
analogue of end-to-end verification in the hardware world.

---

## Class one: it returned, but the content was wrong

### 1. Endpoint silently returns an empty array for historical ranges

**`rpc.flashbots.net`** (Ethereum mainnet, measured 2026-08-10)

Query `eth_getLogs` over historical blocks from the deployment period and it returns
`[]`. No error, no "I don't support archive queries" — just an empty array.

On its own this is survivable. What made it lethal was the combination with another
bug: the scan step size was written as `max_range = max_log_range * 5`, so the window
grew to 50,000, `eth.drpc.org` returned a range error, and the client rotated to the
next endpoint — flashbots — which "successfully" returned `[]`.

Result: **87% of Ethereum's block range was "successfully" scanned, with zero logs.**

Other Ethereum endpoints measured the same day:

| Endpoint | Historical `eth_getLogs` |
|---|---|
| `rpc.mevblocker.io` | ✓ returns normally (2,364 entries) |
| `ethereum-rpc.publicnode.com` | 403 |
| `eth.drpc.org` | HTTP 400 (range exceeded) |
| `eth.merkle.io` | HTTP 400 |
| `eth.meowrpc.com` | 500 |
| `1rpc.io/eth` | explicitly refuses `eth_getLogs` |
| `rpc.flashbots.net` | **silently returns `[]`** ⚠️ (later tests: 504) |

**How it was caught**: not from logs, but from a property of the data. ERC-8004's
`agentId` increments from 0, and the scanned ids formed a contiguous run like
49407–49500 — but the minimum was far above 0. If the scan had really covered the
full range, the minimum id would have to be 0.

**Fix**: hard-clamp the step size to the configured value; run **endpoint integrity
verification** (a canary) before scanning — ask every endpoint about a block known to
contain logs, and drop any endpoint that returns empty. See
[`verify_endpoints_for_logs`](../src/e8004/rpc.py).

### 2. HTTP 200 plus a truncated result set

**celo public RPC** (`celo-rpc.publicnode.com` / `forno.celo.org`, measured 2026-08-13)

This is nastier than returning empty: it returns data, just **not all of it**.

Scanning with a 50,000-block window, celo reported success but came up **1,911 agents
short (19.6% of that chain)**. And **re-querying the identical range returns them**:

```
range [62,232,087, 62,235,907] re-query → 13 Registered entries
  including agentId 3446–3453 — exactly the batch the original scan missed
```

Those 8 consecutive ids share one owner: a batch mint. Batch mints pile thousands of
logs into a very narrow block range, and any window spanning it triggers truncation.

**Fix**: celo's window dropped to 2,000 (hard-coded in config with a note reading
"do not raise back to 50000"). But the real defense is not parameter tuning — see
"The only defense that holds" below.

### 3. Canary verification skipped entirely due to insufficient coverage

This one is my own bug, but it is the same in character and more instructive:
**a defense I added was nullified by another change I made, and the system still
reported success.**

The canary check was implemented as "search backwards from chain head for a block
containing logs", up to 12 × window size. At the default window of 10,000 that covers
120,000 blocks.

I raised scroll's window to 50,000 (because it supports that), so coverage became
600,000 blocks — which sounds like more. But **scroll's registration activity stops
2.3 million blocks before chain head**. No canary found → verification skipped
(rather than erroring) → a silently-empty endpoint sailed through.

Result: `✓ scroll: 0 logs`. Meanwhile the chain plainly has 108 agents, and both
`ownerOf(0)` and `ownerOf(107)` return holders. A rescan produced 470 logs.

**The irony: raising the parameter is what disabled the defense.**

**Fix (two steps; the second is the root cause)**:

1. The canary now probes 24 evenly-spaced windows across the entire range to be
   scanned, newest to oldest (at worst 24 calls, negligible against the hundreds or
   thousands that follow).
2. **But that only raises the hit probability from 1/N to 24/N; it does not change
   what happens when nothing is found.** The original behavior was to record
   `no_canary_found` and **keep scanning** — so "the verifier itself failed" was
   equivalent to "verification passed". The real fix is to change the default:
   when no canary is found, use `ownerOf(0)` via `eth_call` to independently determine
   whether this registry has any tokens at all. **If tokens exist, `Registered` logs
   must have existed too**, so "not a single canary anywhere" can only mean the
   endpoint is withholding logs → **raise, and refuse to scan.**
   Only when there genuinely are no tokens is "zero logs" true and allowed to proceed.

```python
if not allow_unverified and await _token_zero_exists(rpc, reg.identity):
    raise RuntimeError(
        f"{chain.name}: no Registered log found anywhere in [{start:,}, {head:,}] "
        "to use as a canary, but ownerOf(0) returns a holder — this registry does "
        "have tokens, so endpoint integrity cannot be verified. Refusing to scan "
        "rather than produce a silently incomplete dataset."
    )
```

(`--allow-unverified-endpoints` is kept as an explicit escape hatch, needed when you
knowingly scan a narrow window. But **the default is refusal**.)

**The real lesson here is not "probe widely enough". It is:
"the default behavior when the verifier itself fails matters more than the
verification logic."** A fail-open verifier is precisely broken in the abnormal
scenario where it was supposed to earn its keep.

See [`_find_canary_block`](../src/e8004/stages/s02_logs.py) and the test
[`test_scan_guard.py`](../tests/test_scan_guard.py).

### 4. A free tier that caps `eth_getLogs` at 10 blocks

**Alchemy free tier** (measured 2026-08-12, all chains)

```
Under the Free tier plan, you can make eth_getLogs requests with up to a
10 block range.
```

It **does** error, so strictly speaking it is not silent. But the consequence is:
the client recognizes the error as "range too large" and halves the window on retry —
10,000 → 5,000 → … → 10. Then it proceeds to crawl 1.39 million blocks at a
granularity of 10.

No error, no crash — it just **never finishes**. And because it sat first in the
endpoint list, any rotation reaching it stalled the entire round.

**Fix**: a new `log_rpcs` config key — log scanning uses a **separate, empirically
verified list of endpoints that can actually serve historical logs**, instead of
leaving it to rotation and luck. Alchemy must never be in that list.

Worth noting: although Alchemy's free tier cannot do `eth_getLogs`,
`alchemy_getAssetTransfers` can query the entire range with pagination. Ethereum's
49,503 registration records took 50 requests that way, versus 139,186 via
`eth_getLogs`. **Two APIs from the same provider, differing in feasibility by a
factor of 2,700.**

### 5. `|| true` swallowed a failure and let partial data run the whole pipeline

An agent on BSC stuffed raw JSON directly into the `tokenURI` field:

```
{"animal_kingdom": {"kingdoms": 1, ...}}
```

`urlparse` fails **lazily** on input like this — no error at parse time, the exception
only fires when you access `.port`. The `try` block at the time wrapped only
`urlparse()` itself.

One malformed URI crashed the entire fetch stage at 31%. But that step in the pipeline
script ended in `... || true`, so **the crash was swallowed, downstream stages ran to
completion on 31% of the data, and produced a report that looked complete**.

**Fix**: removed `|| true` from the script and added `set -o pipefail` — better to
stop there than to emit something wrong. Added 9 parameterized regression tests for
malformed URIs, and **that batch of tests immediately caught a second instance of the
same class** (`normalize_uri` handling of malformed IPv6).

---

## Class two: it failed, but the error was classified wrong

With these you at least know something went wrong. But **the error message points
somewhere else entirely** — #6 looks like a network problem, #8 looks like data
corruption. Classified wrong, the fix is aimed wrong from the start.

### 6. HTTP 400 not classified as a range error

**celo public RPC**: when there are too many logs in a window it returns **HTTP 400**
rather than a JSON-RPC range error code.

So the halving logic (shrink the window on "range too large") **never fires at all**.
The client only "retries with another endpoint", and both celo endpoints behave the
same way. Retries exhausted → exception → the whole chain crashed, losing all data
for 9,766 agents.

**Fix**: convert a 400 on `eth_getLogs` into a range error for the layer above to
halve. Also added the inverse test — **do not treat every 400 as a range problem**;
a genuine parameter error should surface as an error rather than be masked into an
infinite halving loop.

### 7. Batch call size limit without adaptive backoff

**`mainnet.base.org`**: at most 10 calls per batch; exceeding it returns `-32014`.

The batched block-timestamp query was hard-coded to 100 per batch. Immediate crash,
base lost entirely.

**Fix**: adaptively back off the batch size based on the error text. Measured
**100 → 25 → 6**, finding the ceiling on its own and continuing.

### 8. `DELETE` corrupts the index; one Ctrl-C permanently bricks a table

This one has nothing to do with RPC, and it is not "a whole chain crashed" — it is a
local storage-layer problem. It belongs in this class because its failure mode is
identical: **the error message points somewhere else**, looking like data corruption
when it is actually inconsistent index state.

Derived tables were originally cleared with `DELETE FROM`. DuckDB's `DELETE` maintains
the primary key's ART index row by row, and killing the process midway leaves that
index inconsistent. The next `DELETE`:

```
FATAL Error: Failed to delete all rows from index.
Only deleted 1836 out of 1884 rows.
```

`FATAL` invalidates the entire connection. Which means **one Ctrl-C permanently bricks
that table** — every subsequent operation ends in the same FATAL. And the message
points entirely elsewhere, looking like data corruption.

**Fix**: clearing a derived table is always `DROP` + recreate, which never touches
index contents and is an order of magnitude faster at 390k rows. Added a guard: raw
tables may never be dropped (that data can only be recovered by going back on the
network).

---

## The only defense that holds: reconcile using a property of the data itself

Every item above has a targeted fix, but they share a weakness: **they all defend
against a known failure mode.** Item 3 is the living proof — a defense I added was
nullified by another change I made.

What actually works is a check that **does not depend on upstream being honest**.
In this project that is:

> `agentId` increments from 0 ⇒ **the number of identities with a registration record
> must equal the census count.**

The census comes from `eth_call` (binary search on `ownerOf`); the registration records
come from `eth_getLogs`. Pure SQL, no network, re-runnable at any time:

```
$ e8004 verify-coverage
 chain     census    with record   gap    verdict
 56        262,999   262,999       0      complete
 8453      61,333    61,333        0      complete
 1         49,503    49,503        0      complete
 42220     9,766     9,766         0      complete
 ...
 ✓ registration counts match census on all chains, and the census was not truncated
```

`--strict` turns it into a pipeline gate that exits on mismatch.

### The preconditions for independence have to be spelled out

"Two independent paths corroborating each other" is the strongest claim in this
document, so its preconditions need to be on the table:

**One: the binary search's upper bound must not come from logs.** If the upper bound
for the `ownerOf` binary search were derived from the maximum `agentId` in the logs,
the two paths would **not** be independent — when logs are truncated at the tail, the
census would stop at the same place, the gap would read 0, and the data would in fact
be missing. This is precisely the most dangerous failure mode, because it makes the
gate show green.

The implementation here starts from a **fixed constant**, `hi_guess = 1 << 24`, and
probes exponentially (`[0, 1, 2, 4, …, 2^24]` in one multicall to locate the order of
magnitude, then converges by equidistant steps within the interval), **never reading
any log data**. This is the first place a careful reader should review:
[`count_agents`](../src/e8004/stages/s03_state.py).

**Two: but the "gap is 0" gate itself has the census as its denominator.** The table
above is `FROM agent_state LEFT JOIN registration records` — **if the census itself
is truncated, the missing registration records are not counted either, and the gap
still reads 0.** Independent derivation does not imply independent comparison.

So a second, reverse check was added: **registration records for agents beyond the
census maximum id** have only two possible explanations — new registrations after the
snapshot (normal), or the census converging early (bug). The two are distinguished by
**block number** (not timestamp: the snapshot table's timestamps and on-chain log
timestamps have different bases, and comparing across time zones empirically
misreported all 5 chains as truncated). On the current dataset, 6 chains have records
beyond the maximum, all later than the snapshot block — new registrations after the
snapshot.

**Three: binary search depends on monotonicity, and burns break it.** The search
assumes "all ids < N exist, all ids ≥ N do not". When a token is burned `ownerOf`
reverts, monotonicity breaks, and the search may return an upper bound that is too
low. This is corrected by **probing forward in small batches along the boundary**
(20 ids per batch, 200 consecutive batches), but that can only bridge **gaps shorter
than 20 consecutive ids**. Burns do occur in practice (polygon: 610 mints against 608
extant tokens; Ethereum: 49,722 against 49,503), but they are scattered and form no
large gaps. **The main report's caliber is "burned tokens not excluded", i.e. it
assumes no long contiguous run of burns — that assumption is stated explicitly rather
than ignored.**

A second check of the same shape is that **"zero logs" must be proven**: when a chain
scan yields zero logs, use `ownerOf(0)` via `eth_call` as independent counter-evidence.
Tokens exist on chain but not a single log → **raise immediately**, rather than
quietly returning an empty dataset.

What checks of this kind have in common:

1. **Verify via a second independent path** rather than trusting one source
2. **Exploit structural properties of the data** (monotonic ordering, conservation of
   totals, set containment)
3. **Pure functions, no network** — re-runnable indefinitely
4. **Refuse by default rather than pass by default** — stop on inconsistency instead
   of logging a warning and continuing

---

## A checklist for people building blockchain indexers

1. **Do not trust the "scan completed successfully" signal.** Find an independently
   computable invariant and reconcile against it.
2. **When `eth_getLogs` returns an empty array, suspect the endpoint before the
   chain.** Use a block known to contain logs as a canary, and drop endpoints that
   silently lie.
3. **A larger window has a cost.** Bigger windows are more likely to trigger result-set
   truncation (200 but incomplete), and may cost your window-based verification logic
   its coverage.
4. **Distinguish "range too large" from "transport error".** Some endpoints express a
   range problem as HTTP 400, others as a JSON-RPC error code; misclassify and you get
   either a crash or an infinite loop.
5. **Batch call limits differ per provider and are not published.** Back off adaptively
   based on the error; don't hard-code.
6. **An endpoint that can serve `eth_call` may not serve `eth_getLogs`.** Maintain a
   separate, empirically verified endpoint list for log scanning.
7. **Never use `|| true` in a pipeline script.** Better to stop at the failure than to
   let partial data run to completion and produce a result that looks complete.
8. **Verifiers should fail closed, not fail open.** When a check cannot find its
   evidence (e.g. no canary found at all), the default must be refusal, not passage —
   otherwise the verifier is broken in exactly the abnormal scenario where it matters
   most.
9. **"Independently derived" is not "independently compared".** Two paths not depending
   on each other does not make the comparison between them independent: if the
   comparison uses one as its denominator, then when that one shrinks the other shrinks
   with it and the difference still reads 0. Add a check in the opposite direction.
10. **Public endpoint availability changes.** One endpoint in this document passed the
    canary test and then returned 500 continuously during the real scan. Endpoint lists
    need periodic re-verification, and the system must tolerate single-point failure.

---

## Measured endpoint list (2026-08-15)

Records one property only: whether historical logs from the deployment period can be
retrieved. **This is not a statement about service quality**, and there is no guarantee
it still holds today.

**Ethereum**: `rpc.mevblocker.io` works; publicnode 403, drpc/merkle HTTP 400,
meowrpc 500, 1rpc refuses, flashbots silently empty (later 504).

**Base**: `mainnet.base.org` and `base.gateway.tenderly.co` work
(`base.drpc.org` passed the canary, then returned 500 throughout the real scan);
publicnode 403, meowrpc 500, 1rpc refuses. Tenderly allows a 200,000 span, but
**10,000 is still recommended** — larger windows trigger truncation.

**BSC**: **only `bsc.rpc.blxrbdn.com` works** (5,000 span ceiling); publicnode 403,
all four `dataseed` endpoints `-32005 limit exceeded`, meowrpc does not support
`eth_getLogs`, 1rpc refuses, drpc works but 429s very easily, blockrazor exceeds
limits at even a 1,000 span.

> ⚠️ The first test of the BSC endpoints showed "all unavailable" because I hit them
> **concurrently** and got rate-limited across the board. Serial requests with a 3
> second gap found blxrbdn working. **The testing method itself can contaminate the
> test result.**

**Remaining chains** (tier B, measured maximum `eth_getLogs` span): celo, avalanche,
optimism, mantle, linea and scroll are all 50,000; gnosis is 10,000.
**But celo must be lowered to 2,000** — a 50,000 window triggers silent truncation
(see item 2).

---

## Code and tests

| Defense | Implementation | Test |
|---|---|---|
| Integrity reconciliation (incl. census-truncation reverse check) | `cli.py: verify-coverage` | — |
| Canary endpoint verification (fail closed) | `rpc.py: verify_endpoints_for_logs`, `s02_logs.py: _find_canary_block` | `test_scan_guard.py` |
| Binary-search bound independent of logs | `s03_state.py: count_agents` | — |
| "Zero logs" invariant | `s02_logs.py: _token_zero_exists` | `test_scan_guard.py` |
| HTTP 400 → range error | `rpc.py: RpcError.is_range_error` | `test_scan_guard.py` |
| Adaptive batch backoff | `rpc.py: get_block_timestamps` | `test_scan_guard.py` |
| DROP rather than DELETE for derived tables | `db.py: reset_derived` | `test_db.py` |
| Malformed URIs | `probe/layers.py: parse_endpoint`, `fetch.py: normalize_uri` | `test_parse.py` |

MIT licensed. Reproduction, challenge, and corrections all welcome.
