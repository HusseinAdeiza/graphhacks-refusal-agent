"""The Refusal Agent — an agent that acts on the graph, not on it.

An agent that answers questions about a graph is a dashboard. This one walks
the call graph outward from an unknown contract, matches what it walks into
against real exploit shapes, and — when it finds a match — refuses to certify
and files a BLOCKED CertificationRequest on the graph itself, linked to the
exact path that blocked it.

The loop:

    OBSERVE   given a contract name it has not seen
    TRAVERSE  walk CALLS edges outward, up to MAX_HOPS, recording every path
    DETECT    a path "matches" when any node on it carries a vulnerability
              (HAS_VULNERABILITY) whose SWC is a technique of a real exploit
              (EXPLOITED_BY). Both facts come from the graph.
    ACT       file the CertificationRequest node with status BLOCKED, linked
              to every blocking path and every matched exploit
    RECORD    the filed node is a permanent, replayable record: anyone can
              re-run the same traversal and get the same verdict

Every Cypher query below does multi-hop work. Removing FalkorDB breaks the
product: there is no equivalent of "walk the call graph and match shapes
along the way" in a table store.
"""

import json
import time
import uuid
from dataclasses import dataclass, field, asdict

from data.seed import connect, GRAPH

MAX_HOPS = 6

# ---------------------------------------------------------------------------
# The Cypher the agent depends on. Each query is annotated with WHY it is a
# graph query — these three do work no lookup can do.
# ---------------------------------------------------------------------------

# TRAVERSE: walk CALLS outward from one function to any function up to
# MAX_HOPS away. A variable-length path is a traversal — the answer is the
# whole set of routes, not one row per pair. SQL would need a recursive CTE
# and still not give us the path lists in one shot.
#
# FalkorDB dialect note: the hop bound must be a LITERAL in the pattern —
# `[e:CALLS*1..$hops]` fails with "Encountered unhandled type in inlined
# properties". We expand it from Python (validated integer) instead.
def q_traverse(hops: int) -> str:
    if not isinstance(hops, int) or hops < 1:
        raise ValueError("hops must be a positive integer")
    return f"""
MATCH p = (a:Function {{name: $fn}})-[e:CALLS*1..{hops}]->(b:Function)
RETURN length(p) AS hops,
       [n IN nodes(p) | n.name] AS path,
       [n IN nodes(p) | n.contract] AS contracts
"""

# DETECT: for a path we already walked, which nodes carry a vulnerability
# that a REAL EXPLOIT used? This is a two-hop join (Function ->
# Vulnerability -> Exploit) evaluated per node — the join is the query.
Q_PATH_RISK = """
UNWIND $path AS fname
MATCH (f:Function {name: fname})-[hv:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE hv.status IN ['exploited', 'pattern']
OPTIONAL MATCH (v)-[:EXPLOITED_BY]->(e:Exploit)
RETURN fname, v.swc, v.title, v.severity, hv.status,
       collect(DISTINCT e.name) AS exploits,
       collect(DISTINCT e.loss_usd) AS losses
"""

# What does the contract directly expose? Entry points for the traversal.
Q_ENTRYPOINTS = """
MATCH (c:Contract {name: $contract})-[:HAS_FUNCTION]->(f:Function)
RETURN f.name ORDER BY f.name
"""

@dataclass
class BlockingPath:
    path: list = field(default_factory=list)
    contracts: list = field(default_factory=list)
    hops: int = 0
    findings: list = field(default_factory=list)  # the Q_PATH_RISK rows


@dataclass
class Decision:
    contract: str
    verdict: str                      # CERTIFIED | BLOCKED
    reason: str
    paths_examined: int = 0
    paths_blocked: int = 0
    blocking_paths: list = field(default_factory=list)
    exploits_matched: list = field(default_factory=list)
    library_correlation: list = field(default_factory=list)
    agent_id: str = "refusal-agent-1"
    request_id: str = ""
    filed_at: str = ""


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class RefusalAgent:
    """Certifies contracts. Refuses when the call graph says to."""

    def __init__(self, graph=None):
        self.g = graph or connect()

    # -- OBSERVE ----------------------------------------------------------
    def observe(self, contract: str) -> list:
        """Entry functions of the contract under review."""
        res = self.g.query(Q_ENTRYPOINTS, {"contract": contract})
        return [row[0] for row in res.result_set]

    # -- TRAVERSE ---------------------------------------------------------
    def traverse(self, fn: str, hops: int = MAX_HOPS) -> list:
        """Every CALLS path of length 1..hops from fn. Graph work."""
        res = self.g.query(q_traverse(hops), {"fn": fn})
        paths = []
        for row in res.result_set:
            paths.append(BlockingPath(
                hops=row[0], path=list(row[1]), contracts=list(row[2]),
            ))
        return paths

    # -- DETECT -----------------------------------------------------------
    def detect(self, path: BlockingPath) -> bool:
        """Does any node on this path carry a vulnerability that a REAL
        EXPLOIT used? Fills path.findings and returns True if so.

        The blocking evidence is specifically a vulnerability whose SWC has an
        EXPLOITED_BY edge — a vulnerability that actually appears in a real
        exploit. A 'pattern' status with no exploit behind it is theoretical
        noise, not blocking evidence, and is filtered out here.
        """
        res = self.g.query(Q_PATH_RISK, {"path": path.path})
        path.findings = []
        for row in res.result_set:
            exploits = [e for e in row[5] if e]
            if not exploits:
                continue  # no real exploit used this pattern -> not blocking
            path.findings.append({
                "function": row[0], "swc": row[1], "title": row[2],
                "severity": row[3], "status": row[4],
                "exploits": exploits,
                "losses": [l for l in row[6] if l],
            })
        return bool(path.findings)

