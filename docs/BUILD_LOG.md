# Build log — Graph Hacks 2026 Refusal Agent

Oct 14, 2026 — all work done in-window (submission window opened 18:31 UTC).

## What was built
- `/root/graphhacks-agent` — FalkorDB call-graph agent, Agents Track.
  Seeded 144 nodes / 217 edges; agent refuses to certify 12 contracts with
  named exploit evidence, certifies 4; requests replayable and idempotent.
- Pushed: https://github.com/HusseinAdeiza/graphhacks-refusal-agent

## FalkorDB dialect pitfall found live (new — not in skill notes)
`[e:CALLS*1..$hops]` with a parameterized hop bound fails:
"Encountered unhandled type in inlined properties" — even with an int param,
even via raw GRAPH.QUERY with CYPHER header. Fix: expand the bound as a
literal from validated Python (`*1..6`). The param itself is fine elsewhere
(`{name: $fn}` works); only the variable-length bound rejects it.

## Detection rule refined during testing
First run blocked UniswapV2Router02 on SWC-103 (status "pattern") that has
NO exploit behind it — contradicted the verdict's own wording ("used in a
real exploit"). Fixed: findings with zero EXPLOITED_BY matches are dropped
in `detect()`. Second run: UniswapV2Router02 correctly CERTIFIED.
Aave/Balancer flash loans stay BLOCKED — SWC-105 there has a real
EXPLOITED_BY edge, verified live.

## Test expectation corrected (not the agent)
verify.py initially expected AaveV3Pool/BalancerVault to pass. Live output
showed they block on the flash-loan pattern with real exploit evidence —
the agent was right, the test was wrong. Moved to MUST_BLOCK. 55 checks pass.

## Idempotency fix
First `file()` MERGEd on request_id only, creating duplicate nodes per run.
Now MERGEs on (contract, agent, status) and resets BLOCKED_BY_PATH edges.

## Remaining
- Demo video (< 3 min, required by rules) — NOT yet made.
- Submission form on WeMakeDevs panel — NOT yet submitted.
- Live deployment: README local setup complete; optional deployment later.
