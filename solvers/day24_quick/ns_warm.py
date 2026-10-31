"""Netstring decoder for Day-24 warmup 'String Theory' ("Count carefully. The comma knows where to stop.").
The blob is a stream of netstrings `<len>:<data>,` (one per character on the single_solve). Decoding is applied repeatedly
while the output still parses as a netstring stream (handles nested framing); a trailing/leading whitespace is tolerated.
usage: ns_warm.py <blob file>   (prints decoded text + slug)"""
import re, sys

SLUG = re.compile(r"\b([a-z]+-[a-z]+-[a-z]+-\d{2})\b")


def ns_parse(b):
    """Return list of payloads if b is a complete netstring stream, else None."""
    if isinstance(b, str):
        b = b.encode("latin1")
    b = b.strip()
    out = []
    i = 0
    n_total = len(b)
    if not b:
        return None
    while i < n_total:
        j = b.find(b":", i)
        if j <= i or j - i > 12 or not b[i:j].isdigit():
            return None
        n = int(b[i:j])
        if j + 1 + n >= n_total + 1 or b[j + 1 + n:j + 2 + n] != b",":
            return None
        out.append(b[j + 1:j + 1 + n])
        i = j + 2 + n
    return out


def ns_decode(b, max_depth=8):
    """Peel netstring layers. Returns (text, depth)."""
    cur = b if isinstance(b, bytes) else b.encode("latin1")
    depth = 0
    while depth < max_depth:
        parts = ns_parse(cur)
        if parts is None:
            break
        cur = b"".join(parts)
        depth += 1
    return cur, depth


def slug_of(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    lines = [l for l in text.splitlines() if l.strip()]
    last = lines[-1] if lines else text
    m = SLUG.findall(last)
    if m:
        return m[-1]
    m = SLUG.findall(text)
    return m[-1] if m else None


if __name__ == "__main__":
    raw = open(sys.argv[1], "rb").read()
    t, d = ns_decode(raw)
    print("depth", d)
    print(t.decode("utf-8", "replace"))
    print("SLUG", slug_of(t))
