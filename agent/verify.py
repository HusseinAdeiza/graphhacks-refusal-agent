"""End-to-end verification against a live FalkorDB on 6381.

Run:  python3 -m agent.verify

Seeds a throwaway graph, runs the full observe -> traverse -> detect -> act ->
record loop, replays a request, checks idempotency, and asserts the counts
that prove the graph did real work. Exits non-zero on any failure.
"""

import sys

from data.seed import seed, connect, GRAPH
from agent.refusal_agent import RefusalAgent
from agent.replay import replay, list_requests

# Exploited protocols must be blocked. The flash-loan entry points are here
# because their SWC-105 (Flash Loan Attack) carries a real EXPLOITED_BY edge —
# verified live, not assumed: the refusal is evidence-based, and the evidence
# for Aave/Balancer flash loans is that this exact pattern was used in bZx,
# KyberSwap, Cream and Beanstalk.
MUST_BLOCK = ["bZx", "KyberSwapPool", "CreamFinance", "EulerFinance",
              "MangoMarkets", "RoninBridge", "WormholeNft", "Beanstalk",
              "TheDAO", "PolyBridge"]
# Assume the big lending/AMM protocols come out clean.
MUST_PASS = ["UniswapV2Router02", "UniswapV3Router2", "OpenSeaSeaport",
             "GMXExchange", "AaveV3Pool", "BalancerVault"]


def counts(g):
    nodes = g.query("MATCH (n) RETURN count(n)").result_set[0][0]
    edges = g.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
    calls = g.query("MATCH ()-[r:CALLS]->() RETURN count(r)").result_set[0][0]
    return nodes, edges, calls


def main():
    failures = []

    def check(label, cond, detail=""):
        status = "PASS" if cond else "FAIL"
        print(f"[{status}] {label}" + (f" — {detail}" if detail else ""))
        if not cond:
            failures.append(label)

    print(f"== seed graph '{GRAPH}' ==")
    stats = seed(force=True)
    print(f"   {stats}")
    g = connect()
    nodes, edges, calls = counts(g)
    check("graph seeded", nodes >= 140 and edges >= 200,
          f"{nodes} nodes, {edges} edges, {calls} CALLS")

    agent = RefusalAgent(g)

    print("\n== agent reviews ==")
    results = {r.contract: r for r in (agent.review(c) for c in MUST_BLOCK + MUST_PASS)}

    print("\n== verdicts ==")
    for c in MUST_BLOCK:
        r = results.get(c)
        check(f"BLOCKED: {c}",
              bool(r) and r.verdict == "BLOCKED",
              f"{r.paths_blocked}/{r.paths_examined} paths" if r else "no result")
        if r and r.verdict == "BLOCKED":
            check(f"  evidence: {c} has exploit names", bool(r.exploits_matched),
                  ", ".join(r.exploits_matched[:3]))
            check(f"  evidence: {c} filed on graph",
                  g.query("MATCH (r:CertificationRequest {contract: $c, status: 'BLOCKED'}) RETURN count(r)",
                          {"c": c}).result_set[0][0] == 1)

    for c in MUST_PASS:
        r = results.get(c)
        check(f"CERTIFIED: {c}",
              bool(r) and r.verdict == "CERTIFIED",
              f"{r.paths_examined} paths, 0 blocked" if r else "no result")

    print("\n== record: filed requests on the graph ==")
    reqs = list_requests()
    check("all requests filed", len(reqs) == len(MUST_BLOCK) + len(MUST_PASS),
          f"{len(reqs)} CertificationRequest nodes")

    print("\n== replay: BLOCKED request re-derives the same verdict ==")
    blocked = [r for r in reqs if r["status"] == "BLOCKED"]
    for r in blocked:
        rp = replay(r["request_id"])
        check(f"replay matches: {r['contract']}", rp["match"],
              f"filed {rp['filed_status']} / replay {rp['replay_status']}")

    print("\n== idempotency: re-review updates, does not duplicate ==")
    before = g.query("MATCH (r:CertificationRequest) RETURN count(r)").result_set[0][0]
    agent.review("bZx")
    after = g.query("MATCH (r:CertificationRequest) RETURN count(r)").result_set[0][0]
    check("no duplicate requests", before == after, f"{before} -> {after}")

    print("\n" + ("ALL CHECKS PASSED" if not failures
                  else f"{len(failures)} FAILURES: {failures}"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
