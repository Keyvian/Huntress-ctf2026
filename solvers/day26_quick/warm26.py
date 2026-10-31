"""Day-26 warmup 'Food for Thought' ("A very small language has quite a lot to say." = Brainfuck) solver, all modes.
warm26 = warm25 (imported; it chains warm24 <- warm25 and has a __main__ guard) + a Brainfuck-family codec installed by
monkeypatching warm24.layers / line_decode_l / solve_blob (main() resolves them through the module globals).

bf_candidates() interprets (pure Python, nothing from the artifact is executed as native code):
  * plain Brainfuck      + - < > [ ] . ,        (whitespace / any other byte = comment, ignored)
  * Ook!                 "Ook. Ook? Ook!" pairs  and short Ook (bare . ? ! pairs)
  * any 8-symbol dialect (Alphuck, Pikalang, ReverseFuck, Blub, word tokens...): tokens are mapped structurally - the two
    equal-count properly-nesting tokens are [ ], the output token is the one whose count is a plausible message length,
    the remaining 4 are tried as every permutation of + - < > (<= 24 interpreter runs) and the run whose output names the
    Game Master wins.
usage: warm26.py <challenge> [op=start|retry|practice] [dry]     (env SAVE=<dir> saves start.json+artifact)
       warm26.py local <dir>
       warm26.py bf <file>            (just run one Brainfuck-family file and print its output)"""
import sys, os, re, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm25  # noqa: F401  (installs the Day-25 code-point codec into warm24)
import warm24
from warm24 import inflate, u16, _pr

BF_CMDS = "+-<>[].,"
BF_ONLY = re.compile(r"^[+\-<>\[\].,\s]+$")
OOK_TOK = re.compile(r"Ook[.?!]", re.I)
OOK_MAP = {"..": "+", "!!": "-", ".?": ">", "?.": "<", "!.": ".", ".!": ",", "!?": "[", "?!": "]"}


def bf_compile(prog):
    """RLE-compile a list of BF command chars -> [(op, arg)]; arg = run length for + - < >, jump target for [ ]."""
    code = []
    i = 0
    n = len(prog)
    while i < n:
        c = prog[i]
        if c in "+-<>":
            j = i
            while j < n and prog[j] == c:
                j += 1
            code.append([c, j - i]); i = j
        else:
            code.append([c, 0]); i += 1
    st = []
    for k, (c, _) in enumerate(code):
        if c == "[":
            st.append(k)
        elif c == "]":
            if not st:
                return None
            j = st.pop(); code[k][1] = j; code[j][1] = k
    if st:
        return None
    return code


def bf_run(prog, max_steps=5_000_000):
    """prog: iterable of BF command chars. Returns the output bytes, or None on unbalanced brackets / step cap."""
    code = bf_compile([c for c in prog if c in BF_CMDS])
    if not code:
        return None
    tape = bytearray(1 << 16)
    p = 1 << 15
    out = bytearray()
    i = 0; n = 0; L = len(code)
    while i < L:
        c, a = code[i]
        if c == "+":
            tape[p] = (tape[p] + a) & 0xFF
        elif c == "-":
            tape[p] = (tape[p] - a) & 0xFF
        elif c == ">":
            p += a
        elif c == "<":
            p -= a
        elif c == ".":
            out.append(tape[p])
        elif c == ",":
            tape[p] = 0  # EOF
        elif c == "[":
            if tape[p] == 0:
                i = a
        elif c == "]":
            if tape[p] != 0:
                i = a
        i += 1; n += 1
        if n > max_steps or not (0 <= p < len(tape)):
            return None
    return bytes(out)


def _text(out):
    if not out:
        return None
    u = u16(out)
    if u is not None:
        return u
    try:
        s = out.decode("utf-8")
    except Exception:
        return None
    if sum(ch.isprintable() or ch in "\r\n\t" for ch in s) < 0.9 * len(s):
        return None
    return s


def ook_to_bf(t):
    toks = OOK_TOK.findall(t)
    if len(toks) >= 2 and len(toks) % 2 == 0 and len(OOK_TOK.sub("", t).strip()) == 0:
        pairs = [toks[i][3] + toks[i + 1][3] for i in range(0, len(toks), 2)]
    else:
        c = re.sub(r"\s+", "", t)
        if not c or not re.fullmatch(r"[.?!]+", c) or len(c) % 2:
            return None
        pairs = [c[i:i + 2] for i in range(0, len(c), 2)]
    if any(p not in OOK_MAP for p in pairs):
        return None
    return "".join(OOK_MAP[p] for p in pairs)


def _nests(seq, a, b):
    d = 0
    for x in seq:
        if x == a:
            d += 1
        elif x == b:
            d -= 1
            if d < 0:
                return False
    return d == 0


def generic_bf(t):
    """8-symbol (or 7, when ',' is unused) substitution dialect -> [bf outputs]. Deliberately strict (a real program has
    >= 64 tokens, <= 8 distinct symbols, an output symbol used >= 20 times and exactly one properly-nesting equal-count
    bracket pair) so that ordinary rows / intermediate texts never trigger the (expensive) permutation runs."""
    t = t.strip()
    if not t or re.search(r"\d", t) and len(set(re.sub(r"\s+", "", t))) > 8:
        return []
    toks = t.split()
    if len(set(toks)) > 8 or len(toks) < 64:
        toks = list(re.sub(r"\s+", "", t))
    syms = sorted(set(toks), key=lambda s: -toks.count(s))
    if not 5 <= len(syms) <= 8 or len(toks) < 64:
        return []
    cnt = {s: toks.count(s) for s in syms}
    res = []
    # brackets: a pair with equal counts that nests; output: count that looks like a message (20..400)
    pairs = [(a, b) for a in syms for b in syms if a != b and 1 <= cnt[a] == cnt[b] and _nests(toks, a, b)]
    if not pairs or not any(20 <= cnt[s] <= 400 for s in syms):
        return []
    runs = 0
    for a, b in pairs[:4]:
        rest = [s for s in syms if s not in (a, b)]
        outs = [s for s in rest if 20 <= cnt[s] <= 400]
        for o in outs[:2]:
            others = [s for s in rest if s != o]
            if len(others) > 5:
                continue
            for perm in itertools.permutations("+-<>,", len(others)):
                if len(others) == 4 and "," in perm:
                    continue
                m = dict(zip(others, perm)); m[a] = "["; m[b] = "]"; m[o] = "."
                prog = [m[x] for x in toks]
                if prog.count("+") < prog.count("-"):  # messages are built with far more + than -
                    continue
                runs += 1
                if runs > 48:
                    return res
                s = _text(bf_run(prog, 300_000))
                if s and "game master" in s.lower():
                    res.append(s)
                    return res
    return res


def bf_candidates(t, generic=True):
    """[(label, text)] Brainfuck-family decodings of a text blob (the blob is treated as ONE program)."""
    out = []
    tt = t.strip()
    if not tt:
        return out
    if BF_ONLY.match(tt) and sum(c in BF_CMDS for c in tt) >= 8:
        s = _text(bf_run(tt))
        if s:
            out.append(("bf", s))
    bf = ook_to_bf(tt)
    if bf:
        s = _text(bf_run(bf))
        if s:
            out.append(("ook", s))
    if generic and not out and not BF_ONLY.match(tt):
        for s in generic_bf(tt):
            out.append(("bfx", s))
    return out


def is_bfish(t):
    tt = t.strip()
    return bool(BF_ONLY.match(tt)) and sum(c in BF_CMDS for c in tt) >= 8 or bool(OOK_TOK.search(tt)) or \
        bool(re.fullmatch(r"[.?!\s]+", tt))


_orig_layers25 = warm24.layers
_orig_line_decode_l25 = warm24.line_decode_l
_orig_solve_blob25 = warm24.solve_blob


def layers(s):
    t = re.sub(r"^\d+\t", "", s.strip())
    res = [x for lab, x in bf_candidates(t)]
    if res and is_bfish(t):
        return res  # a Brainfuck program is unambiguous: do not fan out into the rot/atbash/base64 soup
    return res + _orig_layers25(s)


def line_decode_l(f):
    out = _orig_line_decode_l25(f)
    ff = f.rstrip("\r\n")
    extra = []
    for lab, x in bf_candidates(ff, generic=False):  # rows: plain Brainfuck / Ook only (the dialect search is whole-blob)
        p = _pr(x) if all(ord(c) < 128 for c in x) else x
        if p is not None and p not in [o[1] for o in out] and p not in [o[1] for o in extra]:
            extra.append((lab, p))
    if extra and is_bfish(ff):
        return extra + out  # explicit Brainfuck row: its decode goes first
    return out + extra


def solve_blob(raw):
    """Brainfuck-first: if the whole blob is one program, run it and hand the text to the Day-25 solver (which also handles a
    non-BF blob or a program whose output is itself another codec)."""
    r = raw
    for _ in range(4):
        d = inflate(r)
        if d is None:
            break
        r = d
    s = u16(r)
    if s is None:
        s = r.decode("utf-8", "replace")
    for lab, c in bf_candidates(s):
        slug, msg = _orig_solve_blob25(c.encode("utf-8"))
        if slug:
            return slug, msg
    return _orig_solve_blob25(raw)


# ---- row-codec precedence (bug found on the Day-26 mastery, blobs 22/106): the per-position ranks learned by
# warm24.learn_positions() order labels by average English score, and on 4-character slug fragments the rot47 "decode" of a
# framed Ascii85 row (`<~@psG#~>` -> 'kOoADvROm') out-scored the real a85 decode ('cast'); the lowercase template search then
# accepted the garbage as a slug word. A row written in a STRICT-syntax codec (framing / alphabet / padding that a substitution
# cipher cannot produce by accident) is unambiguous, so such candidates always go before the rot/caesar/atbash/reverse/rail soup.
STRONG_LABELS = {"a85", "ns", "cpU", "cpbs", "cpx", "cphtmlx", "cphtml", "cp0x", "bf", "ook", "bfx", "json", "html", "url",
                 "bin", "dec", "oct", "hex", "b32", "morsehex", "morseb32", "morsedec", "morse", "morselow", "baconhex",
                 "baconhexstr", "bacon", "bacon24", "baconup"}


def _strong(lab, row):
    if lab in STRONG_LABELS or lab.endswith("gz") or lab.endswith("16"):
        return True
    if lab in ("b64", "b64u") and "=" in row:
        return True
    return False


_orig_solve_mixed24 = warm24.solve_mixed


def solve_mixed(s):
    rows = warm24._rows(s)
    if not rows:
        return None
    cands = []
    for i, f in rows:
        lc = warm24.line_decode_l(f)
        if not lc:
            return None
        rank = warm24.POS_RANK.get(i)
        if rank:
            lc.sort(key=lambda t: (0 if _strong(t[0], f) else 1, rank.index(t[0]) if t[0] in rank else 99,
                                   -warm24.eng_score(t[1])))
        else:
            lc.sort(key=lambda t: (0 if _strong(t[0], f) else 1, -warm24.eng_score(t[1])))
        cands.append([x for _, x in lc])
    r = warm24.solve_template(cands)
    if r:
        return r
    return _orig_solve_mixed24(s)


warm24.solve_mixed = solve_mixed
warm24.layers = layers
warm24.line_decode_l = line_decode_l
warm24.solve_blob = solve_blob

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "bf":
        b = open(sys.argv[2], "rb").read()
        for lab, x in bf_candidates(b.decode("utf-8", "replace")):
            print(lab, "|", x)
        sys.exit(0)
    warm24.main()
