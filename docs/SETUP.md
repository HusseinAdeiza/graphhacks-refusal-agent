# Graph Hacks 2026 — Refusal Agent (Track: Agents That Act on Connected Data)

Built during the hackathon window (Oct 14–18, 2026). The seed dataset is
public (SWC registry + exploit post-mortems); all application code is new.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# FalkorDB on host port 6381 (skip if already running):
docker run -d --name graphhacks-agent -p 6381:6379 falkordb/falkordb:latest

python3 -m data.seed --force   # seed the graph
python3 -m agent.refusal_agent # run the agent
python3 -m agent.verify        # end-to-end verification
```

## Track

**Agents That Act on Connected Data** — the agent traverses a FalkorDB call
graph, detects an exploit path, refuses to certify, and files a BLOCKED
CertificationRequest on the graph.
