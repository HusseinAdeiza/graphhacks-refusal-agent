"""Replay a filed CertificationRequest against the current graph.

This is the RECORD half of the loop: a BLOCKED request on the graph is a
permanent, replayable artifact. Anyone (another agent, a judge) can load the
request, re-run the exact traversal that produced the verdict, and get the
same answer — because the evidence path is stored on the graph, not in a log.
"""

import json

from agent.refusal_agent import RefusalAgent


def replay(request_id: str):
    """Re-derive the verdict for a filed request from the graph."""
    agent = RefusalAgent()
    res = agent.g.query(
        """
        MATCH (r:CertificationRequest {request_id: $rid})-[:FILED_AGAINST]->(c:Contract)
        RETURN r.agent_id, r.status, r.reason, r.filed_at, r.evidence_json, c.name
        """,
        {"rid": request_id},
    )
    if not res.result_set:
        raise KeyError(f"no CertificationRequest with id {request_id}")
    agent_id, status, reason, filed_at, evidence_json, contract = res.result_set[0]

    # Re-run the review and compare to the filed verdict.
    fresh = agent.review(contract)

    stored = json.loads(evidence_json or "{}")
    return {
        "request_id": request_id,
        "contract": contract,
        "filed_agent": agent_id,
        "filed_status": status,
        "filed_at": filed_at,
        "filed_reason": reason,
        "filed_paths_blocked": stored.get("paths_blocked", []),
        "replay_status": fresh.verdict,
        "replay_paths_blocked": fresh.paths_blocked,
        "replay_exploits": fresh.exploits_matched,
        "match": fresh.verdict == status,
    }


def list_requests():
    """All filed requests, newest first."""
    agent = RefusalAgent()
    res = agent.g.query(
        """
        MATCH (r:CertificationRequest)-[:FILED_AGAINST]->(c:Contract)
        RETURN r.request_id, c.name, r.status, r.paths_examined, r.paths_blocked, r.filed_at
        ORDER BY r.filed_at DESC
        """
    )
    return [
        {
            "request_id": row[0], "contract": row[1], "status": row[2],
            "paths_examined": row[3], "paths_blocked": row[4], "filed_at": row[5],
        }
        for row in res.result_set
    ]


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(json.dumps(replay(sys.argv[1]), indent=2))
    else:
        for r in list_requests():
            print(f"{r['request_id']}  {r['status']:9s} {r['contract']}  "
                  f"({r['paths_blocked']}/{r['paths_examined']} paths blocked)")
