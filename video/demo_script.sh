#!/usr/bin/env bash
# Demo script — runs the REAL agent against the live FalkorDB, with paced
# holds so a viewer can read each section. Every command + output is real.
# Order mirrors the agent loop: seed -> review(4) -> verify(full 16) -> record.
cd /root/graphhacks-agent || exit 1
export TERM=xterm-256color
clear
echo "REFUSAL AGENT"
echo "Graph Hacks 2026 - WeMakeDevs x FalkorDB - Agents That Act on Connected Data"
echo ""
echo "Loop:  OBSERVE -> TRAVERSE -> DETECT -> ACT -> RECORD"
sleep 6

clear
echo "\$ python3 -m data.seed --force"
echo "# seeds 23 real protocols: 144 nodes / 217 edges in FalkorDB"
python3 -m data.seed --force
sleep 6

clear
echo "\$ python3 -m agent.refusal_agent"
echo "# walks the call graph, matches against real exploits, files its verdict"
python3 -m agent.refusal_agent
sleep 20

clear
echo "\$ python3 -m agent.verify"
echo "# full 16-contract suite: review + file + replay + idempotency"
python3 -m agent.verify 2>&1 | grep -E 'replay matches|no duplicate|ALL CHECKS'
sleep 12

clear
echo "\$ python3 -m agent.show_filed"
echo "# the ACT, persisted on the graph: every filed CertificationRequest"
python3 -m agent.show_filed
sleep 14

clear
echo "\$ python3 -m agent.show_filed KyberSwapPool"
python3 -m agent.show_filed KyberSwapPool
sleep 14

clear
echo ""
echo "12 contracts BLOCKED with named exploit evidence.  4 CERTIFIED."
echo "Every filed request is replayable: re-run the traversal, same verdict."
echo ""
echo "github.com/HusseinAdeiza/graphhacks-refusal-agent"
sleep 6
