#!/bin/bash
# Day-31 mastery driver: live start + fetch + compute, then bank the new family and submit the rest.
# Submits only when every answer computed; a partial compute stops here for inspection.
C=script-analysis-day-31-xslt-final-gauntlet/mastery
P=~/ctf-venv/bin/python
NEW=polyglot-xslt
cd ~/d31 || exit 1
$P tools/s23.py $C --save scr_m > m_run.log 2>&1
cut -c1-300 m_run.log | tail -4
$P -c '
import json, sys
s = json.load(open("scr_m/start.json")); a = json.load(open("scr_m/answers.json"))
ids = s.get("answer_ids") or [q["id"] for q in s["questions"]]
miss = [i for i in ids if i not in a]
print("mode", s.get("mode"), "deadline", s.get("deadline"), "run_for_time", s.get("run_for_time"),
      "ids", len(ids), "answered", len(a), "missing", len(miss), miss[:8])
sys.exit(1 if miss else 0)
' || { echo "NOT SUBMITTING: incomplete answers"; exit 2; }
N=$($P -c '
import json, re
s = json.load(open("scr_m/start.json"))
print(max([int(m.group(1)) for q in s["questions"] for m in [re.match(r"set(\d+)\.", q["id"])] if m] or [1]))')
echo "sets=$N"
$P tools/s23.py $C --dir scr_m --submit --by-file --only $NEW --files $N > m_bank.log 2>&1
cut -c1-200 m_bank.log | tail -7
if grep -q "^BAD_GROUPS \[\]" m_bank.log; then
  $P tools/s23.py $C --dir scr_m --submit --exclude $NEW > m_rest.log 2>&1
  cut -c1-300 m_rest.log | tail -3
else
  echo "BANK HAD BAD GROUPS: not submitting the rest"
fi
