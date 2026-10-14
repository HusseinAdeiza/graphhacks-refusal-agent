"""Seed the FalkorDB graph for the Refusal Agent.

The seed data is a public dataset compiled from:
  - SWC registry (swcregistry.io) — the 20 vulnerability patterns
  - public exploit post-mortems — the 10 exploits, their years, losses, chains
  - public contract metadata — names, chains, kinds, protocols

Data (public sources) is transferable; the graph-building code in this repo
is all new work written during the Graph Hacks window.

Two-pass seeding is required by FalkorDB: CREATE never links to a node that
does not exist yet, and it fails silently when it doesn't. Pass 1 creates
every node; pass 2 creates every edge. Do not merge the passes.
"""

from falkordb import FalkorDB

from data.contracts import CONTRACTS, FUNCTIONS, LIBRARIES, USES_LIBRARY, AUDITORS
from data.exploits import EXPLOITS
from data.vulnerabilities import VULNERABILITIES, SEVERITY_RANK

HOST = "127.0.0.1"
PORT = 6381
GRAPH = "graphhacks-agent"

# FalkorDB client signature is query(cypher, params=None); collect the
# statements as plain strings and send params inline is NOT safe (user-ish
# data), so keep the (statement, params) pairs and pass params to query().
# The client's query() accepts params as the second positional argument.
Statements = list  # of (cypher, params-dict) tuples


def connect():
    return FalkorDB(host=HOST, port=PORT).select_graph(GRAPH)


def _node_statements():
    stmts = []
    for c in CONTRACTS:
        stmts.append((
            "MERGE (c:Contract {name: $name}) "
            "SET c.address = $address, c.chain = $chain, c.kind = $kind, c.protocol = $protocol",
            dict(c),
        ))
    for lib in LIBRARIES:
        stmts.append((
            "MERGE (l:Library {name: $name}) SET l.version = $version, l.usage = $usage",
            dict(lib),
        ))
    for v in VULNERABILITIES:
        params = dict(v)
        params["severity_rank"] = SEVERITY_RANK[v["severity"]]
        stmts.append((
            "MERGE (v:Vulnerability {swc: $swc}) "
            "SET v.title = $title, v.severity = $severity, v.category = $category, "
            "v.description = $description, v.mitigation = $mitigation, "
            "v.severity_rank = $severity_rank",
            params,
        ))
    for e in EXPLOITS:
        stmts.append((
            "MERGE (e:Exploit {name: $name}) "
            "SET e.year = $year, e.loss_usd = $loss_usd, e.chain = $chain, e.summary = $summary",
            {k: e[k] for k in ("name", "year", "loss_usd", "chain", "summary")},
        ))
    for fname, (contract, description, _calls, _vulns) in FUNCTIONS.items():
        stmts.append((
            "MERGE (f:Function {name: $name}) "
            "SET f.description = $description, f.contract = $contract",
            {"name": fname, "description": description, "contract": contract},
        ))
    for auditor, _c in AUDITORS:
        stmts.append(("MERGE (a:Auditor {name: $name})", {"name": auditor}))
    return stmts


def _edge_statements():
    stmts = []
    for fname, (_contract, _desc, calls, vulns) in FUNCTIONS.items():
        for target in calls:
            stmts.append((
                "MATCH (a:Function {name: $src}), (b:Function {name: $dst}) "
                "MERGE (a)-[:CALLS]->(b)",
                {"src": fname, "dst": target},
            ))
        for swc, source, status in vulns:
            stmts.append((
                "MATCH (f:Function {name: $name}), (v:Vulnerability {swc: $swc}) "
                "MERGE (f)-[:HAS_VULNERABILITY {source: $source, status: $status}]->(v)",
                {"name": fname, "swc": swc, "source": source, "status": status},
            ))
    for fname, (contract, *_rest) in FUNCTIONS.items():
        stmts.append((
            "MATCH (c:Contract {name: $contract}), (f:Function {name: $name}) "
            "MERGE (c)-[:HAS_FUNCTION]->(f)",
            {"contract": contract, "name": fname},
        ))
    for lib, contract in USES_LIBRARY:
        stmts.append((
            "MATCH (l:Library {name: $lib}), (c:Contract {name: $contract}) "
            "MERGE (c)-[:USES_LIBRARY]->(l)",
            {"lib": lib, "contract": contract},
        ))
    for auditor, contract in AUDITORS:
        stmts.append((
            "MATCH (a:Auditor {name: $auditor}), (c:Contract {name: $contract}) "
            "MERGE (a)-[:AUDITED]->(c)",
            {"auditor": auditor, "contract": contract},
        ))
    for e in EXPLOITS:
        for swc in e["techniques"]:
            stmts.append((
                "MATCH (v:Vulnerability {swc: $swc}), (e:Exploit {name: $name}) "
                "MERGE (v)-[:EXPLOITED_BY]->(e)",
                {"swc": swc, "name": e["name"]},
            ))
    return stmts


def seed(force=False):
    """Build the graph. force=True deletes an existing graph first."""
    db = FalkorDB(host=HOST, port=PORT)
    if force:
        try:
            db.select_graph(GRAPH).delete()
        except Exception:
            pass
    g = db.select_graph(GRAPH)

    nodes = _node_statements()
    edges = _edge_statements()
    for stmt, params in nodes + edges:
        g.query(stmt, params)

    return {
        "graph": GRAPH,
        "node_statements": len(nodes),
        "edge_statements": len(edges),
    }


if __name__ == "__main__":
    import sys
    print(seed(force="--force" in sys.argv))
