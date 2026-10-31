"""Day-23 'LYR' layered-encoding decoder.

Header form:  HUNTRESS_ANALYSIS_V1:LYR-<layer>_<layer>_..._<layer>-<payload>
The chain lists the encodings in the order they were APPLIED, so decoding walks it
right-to-left (the right-most layer is the outer-most wrapper on the payload).

Layers seen on Day 23: hex, b64, b32, rev (string reversal), frag (dot-separated chunks).
`decode_layers` is strict (follows the chain); `auto_decode` is a chain-agnostic fallback
that peels wrappers by sniffing, so a variant inventing a new chain order still decodes.
"""
import re, base64, binascii

PLAN_RE = re.compile(r"^\s*v=\d+\|")


def plan_like(t):
    return bool(t) and bool(PLAN_RE.match(t)) and ("campaign" in t or "steps" in t)


def _defrag(s):
    return re.sub(r"[.\s_|:,-]", "", s)


def _hex(s):
    s = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(s) % 2:
        raise ValueError("odd hex")
    return bytes.fromhex(s).decode("ascii")


def _b64(s):
    s = re.sub(r"\s", "", s).replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("ascii")


def _b32(s):
    s = re.sub(r"[^A-Z2-7=]", "", re.sub(r"\s", "", s).upper())
    s = s.rstrip("=")
    return base64.b32decode(s + "=" * (-len(s) % 8)).decode("ascii")


LAYERS = {"hex": _hex, "b64": _b64, "b32": _b32, "rev": lambda s: s[::-1], "frag": _defrag}


def decode_layers(chain, payload):
    """Apply the named layers right-to-left. Returns the decoded text or None."""
    t = payload
    try:
        for name in reversed([c for c in chain.split("_") if c]):
            fn = LAYERS.get(name)
            if fn is None:
                return None
            t = fn(t)
    except Exception:
        return None
    return t


def auto_decode(payload, depth=8):
    """Chain-agnostic peel: try every layer at each step, keep whatever reaches a plan."""
    seen = set()
    stack = [(payload, 0)]
    while stack:
        t, d = stack.pop()
        if plan_like(t):
            return t
        if d >= depth or t in seen or len(t) > 200000:
            continue
        seen.add(t)
        for name in ("frag", "hex", "b64", "b32", "rev"):
            try:
                nt = LAYERS[name](t)
            except Exception:
                continue
            if nt and nt != t and nt.isprintable() or (nt and plan_like(nt)):
                stack.append((nt, d + 1))
    return None


HEADER = re.compile(r"HUNTRESS_ANALYSIS_V1:LYR-([a-z0-9_]+)-([A-Za-z0-9+/=._\-]+)")


def from_text(text):
    """Find and decode a LYR header in a specimen. Returns (plan_text, chain) or (None, None)."""
    m = HEADER.search(text)
    if not m:
        return None, None
    chain, payload = m.group(1), m.group(2)
    t = decode_layers(chain, payload)
    if not plan_like(t):
        t = auto_decode(payload)
    return (t if plan_like(t) else None), chain


if __name__ == "__main__":
    import sys, os
    d = sys.argv[1]
    ok = bad = 0
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f)
        if not os.path.isfile(p):
            continue
        t = open(p, encoding="utf-8-sig", errors="replace").read()
        if "LYR-" not in t:
            continue
        plan, chain = from_text(t)
        strict = decode_layers(chain, HEADER.search(t).group(2)) if chain else None
        tag = "OK " if plan else "BAD"
        if plan:
            ok += 1
        else:
            bad += 1
        print("%s %-22s %-18s strict=%s %s" % (tag, f, chain, "y" if plan_like(strict) else "n",
                                               (plan or "")[:140]))
    print("decoded", ok, "failed", bad)
