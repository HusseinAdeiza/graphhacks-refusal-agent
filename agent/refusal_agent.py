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

