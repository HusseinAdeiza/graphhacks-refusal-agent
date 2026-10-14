# Graph Hacks — Pre-Window Plan (Agents Track)

**Status:** prep notes only. Rule 7 forbids code before Oct 15 12:01 AM IST.
Written Oct 8, 2026. Track: **Agents That Act on Connected Data**.

---

## Why this track

Provenance already proved the pattern we're strongest at: an agent driving a
real system through a tool interface, where the *system* enforces the rules and
the agent is not trusted to behave. The MCP server + eval harness from
Provenance transfers directly — it's a proven, tested shape.

"Act on connected data" is the differentiator. Most submissions will build an
agent that *answers questions about* a graph. We build one that **traverses the
graph and takes an action because of what the traversal found.** Query → decide
→ act → record. The action is the point.

---

## The retweetable sentence (playbook rule A1)

> An agent that reads a protocol's call graph, finds the path a real exploit
> took, and refuses to certify the contract until that path is closed.

If we can't say this in one line, we don't have an idea yet. This one holds.

---

## Rule 3 test — the graph must do real work

Every design decision gets this test: **remove FalkorDB, does the product
break?** If the answer is "we could use Postgres instead," the graph is
decoration and the entry is dead.

What makes it genuinely graph-dependent:
- `cross_contract_attack_chain` — a 2–6 hop `CALLS` path crossing protocol
  boundaries. This is a traversal, not a lookup. No SQL equivalent.
- `attack_path` — shortest path between two functions over call edges.
- `library_risk_correlation` — a multi-hop join: Library → Contract → Exploit.
  Doing this by hand is a spreadsheet nightmare; in Cypher it's one query.

These are structural. The agent cannot function without them.

---

## The agent's loop (the thing that makes it "acts on")

1. **Observe** — agent is given a contract it has not seen
2. **Traverse** — walks the call graph outward from that contract's functions
3. **Detect** — identifies whether any traversed path matches a known exploit
   shape (the graph holds 10 real exploits with their actual entry functions)
4. **Act** — the action: file a `CertificationRequest` node on the graph with
   status `BLOCKED`, linked to the exact path that blocked it
5. **Record** — the request is replayable: another agent (or a judge) can load
   the same node and re-run the check against the same path

Step 4 is the whole submission. A system that only *reports* risk is a
dashboard. A system that **refuses to certify** is an agent acting on the graph.

---

## What is legitimately transferable from AuditGraph

Rule 8 allows: frameworks, open-source libraries, public APIs, templates,
public datasets. Rule 7 requires main work to begin in-window.

**Allowed (public data / knowledge):**
- The seed dataset — SWC registry + public exploit post-mortems. Public sources,
  and it's *data*, not our application code.
- Domain knowledge of which patterns stack, which libraries carry loss.
- The 8 Cypher query *shapes* as concepts — but rewritten live, not copy-pasted.

**Not allowed (our pre-window application code):**
- The FastAPI backend, React frontend, Cytoscape views, PDF export, ingestion
  endpoints, docker compose. All built Sep 24 – Oct 1.
- Reusing that code would mean the main work began pre-window.

So: the *data* and the *domain* carry over. The *code* gets written from
scratch inside the window. That's the line.

---

## Honest scope for 3.5 days

**In:**
- FalkorDB schema: Contract, Function, Library, Vulnerability, Exploit,
  CertificationRequest
- Seed: ~20 contracts, ~50 call edges, the SWC patterns, ~10 real exploits
- 3 Cypher templates that do genuine multi-hop work (attack chain, attack path,
  library correlation)
- Agent loop: observe → traverse → detect → **act** (file BLOCKED request)
- One screen showing the agent's traversal + the filed request
- README with the data model documented
- Demo video < 3 min

**Out (cut first if time runs short):**
- Ingestion endpoints (Etherscan/Slither)
- PDF report export
- Graph algorithms beyond what the agent needs
- Frontend polish beyond one clear screen

---

## Rule 11 readiness

Judges can ask us to explain the graph model, the queries, the architecture,
and every technical decision. So: every Cypher query gets a comment saying
*what it does and why it's a graph query and not a lookup*. BUILD_LOG.md
continues from Provenance — decisions dated, bugs found and fixed.

---

## Known risks

- **3.5 days is tight.** The agent loop is the minimum viable product; everything
  else is cut if it threatens that.
- **FalkorDB Cypher quirks** (from AuditGraph notes): `shortestPath()` only in
  RETURN, no `elementId()`, `LIMIT $param` rejects string-typed params. Budget
  time for these.
- **No pre-written code allowed** means day 1 is slower than it feels like it
  should be. That's the cost of a legitimate entry.
