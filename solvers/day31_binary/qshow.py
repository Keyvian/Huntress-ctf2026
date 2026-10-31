"""qshow.py <status.json> <id regex> -- print full question text + answer_format for matching ids."""
import json, sys, re
j = json.load(open(sys.argv[1]))
for q in j["questions"]:
    if re.search(sys.argv[2], q["id"]):
        print(q["id"], "| art:", q.get("artifact"))
        print("   Q:", q["question"])
        print("   F:", json.dumps(q.get("answer_format")), "| norm:", q.get("normalization"))
