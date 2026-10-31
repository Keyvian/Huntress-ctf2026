"""usage: psdump.py <dir-with-extracted-files> -> print the decoded JSON of each composite .ps1 fixture"""
import sys, os, re, json, base64

d = sys.argv[1]
for f in sorted(os.listdir(d)):
    if not f.endswith(".ps1"):
        continue
    t = open(os.path.join(d, f), encoding="utf-8-sig", errors="replace").read()
    m = re.search(r"FromBase64String\('([^']+)'\)", t)
    print("=" * 20, f, "len", len(t))
    if not m:
        print("   no base64 material; head:")
        print("   " + t[:400].replace("\n", "\n   "))
        continue
    raw = base64.b64decode(m.group(1))
    km = re.search(r"-bxor\s+(0x[0-9a-fA-F]+|\d+)", t)
    if km:
        raw = bytes(v ^ int(km.group(1), 0) for v in raw)
    if "[Array]::Reverse" in t:
        raw = raw[::-1]
    try:
        print("   JSON:", json.dumps(json.loads(raw), indent=None))
    except Exception as e:
        print("   RAW:", raw[:400], e)
    # which keys the script body references, and any scenario hints
    print("   refs:", sorted(set(re.findall(r"\$record\.([a-z])", t))),
          "| plan-ish:", sorted(set(re.findall(r"\$\w*[Pp]lan\w*", t))))
    hints = re.findall(r"(?m)^\s*#.*$", t)
    for h in hints[:4]:
        print("   #:", h.strip())
    print("   nativeTypes:", re.findall(r"\$nativeTypes\s*=\s*@\(([^)]*)\)", t))
    print("   emit:", re.findall(r"\[pscustomobject\]@\{[^}]*\}", t))
