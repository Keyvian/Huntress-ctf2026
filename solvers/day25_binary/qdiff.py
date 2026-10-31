"""qdiff.py <old start.json|status.json> <new start.json|status.json> -- diff two question contracts by id/text."""
import json, sys


def load(p):
    j = json.load(open(p))
    return {q["id"]: q["question"] for q in j["questions"]}


old, new = load(sys.argv[1]), load(sys.argv[2])
gone = [k for k in old if k not in new]
added = [k for k in new if k not in old]
changed = [k for k in old if k in new and old[k] != new[k]]
print("old", len(old), "new", len(new))
print("gone", gone)
print("new", added)
print("changed", changed)
for k in changed:
    print("CHANGED", k)
    print(" OLD:", old[k][:500])
    print(" NEW:", new[k][:500])
