import sys, time, re, ast
sys.path.insert(0, "~/ctf")
from gm import GM

g = GM()
base = "binary-reverse-engineering-day-27-compiler-attribution"
for ch in (base, base + "/time_trial", base + "/mastery"):
    d = 1.5
    for _ in range(8):
        r = g.status(ch)
        if not (isinstance(r, dict) and r.get("error") == "rate_limited"):
            break
        time.sleep(d); d = min(d * 1.6, 10)
    print(ch, {k: r.get(k) for k in ("mode", "result", "flag", "solved", "deadline", "error")})
    time.sleep(1.5)

# per-set d27 diag summary from the saved run logs
for lg in sys.argv[1:]:
    for line in open(lg):
        if not line.startswith("SET "):
            continue
        k = line.split()[1]
        def grab(key):
            m = re.search(r"'%s': (\(.*?\)|\[.*?\])(?=, '|\}$)" % key, line)
            return m.group(1) if m else None
        print(lg.split("/")[-2], "set", k, grab("d27_order"), grab("d27_gcc_cfg"), grab("d27_tcc_cfg"),
              grab("d27_configs_equal"), "MISMATCH" if "d27_CONFIG_MISMATCH" in line else "",
              "NOHCFG" if "NO_HCFG" in line else "")
        print("    roles", grab("d27_roles"))
