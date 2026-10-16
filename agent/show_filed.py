"""Inspect a filed CertificationRequest and its evidence chain on the graph.

Usage:
    python3 -m agent.show_filed            # all filed requests
    python3 -m agent.show_filed <contract> # one request + its blocked paths
"""
import sys

from data.seed import connect


def main(contract: str | None = None):
    g = connect()
    if contract:
        rows = g.query(
            """
            MATCH (cr:CertificationRequest {contract: $c})
                 -[:FILED_AGAINST]->(c:Contract)
            OPTIONAL MATCH (cr)-[bp:BLOCKED_BY_PATH]->(f:Function)
            RETURN cr.status, cr.reason, cr.paths_examined,
                   cr.paths_blocked, collect(f.name) AS blocked
            """,
            {"c": contract},
        ).result_set
        if not rows:
            print(f"no CertificationRequest filed for '{contract}'")
            return
        st, reason, examined, blocked, fns = rows[0]
        print(f"request:   {contract}")
        print(f"status:    {st}")
        print(f"reason:    {reason}")
        print(f"paths:     {blocked} of {examined} blocked")
        named = [x for x in fns if x]
        if named:
            print("blocked_by:")
            for f in named:
                print(f"  - {f}")
    else:
        rows = g.query(
            """
            MATCH (cr:CertificationRequest)
            RETURN cr.contract, cr.status, cr.paths_blocked
            ORDER BY cr.contract
            """
        ).result_set
        for c, st, b in rows:
            print(f"{c:22} {st:10} paths_blocked={b}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
