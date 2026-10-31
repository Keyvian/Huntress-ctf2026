#!/usr/bin/env python3
"""Lightweight CTF knowledge index (SQLite FTS5 / BM25). No external deps.
  kb.py reindex          rebuild the index from source files
  kb.py query "<terms>"  top matches with snippets
Upgrade path: add a sqlite-vec vector table for hybrid search if the corpus grows.
"""
import os, sys, glob, sqlite3

DB = "~/ctf/kb.db"
MEM = "/mnt/c/Users/<user>/.claude/projects/C--Users-<user>-Documents-Huntress-CTF/memory"
PROJ = "/mnt/c/Users/<user>/Documents/Huntress CTF"
SRC_GLOBS = [
    MEM + "/*.md",
    PROJ + "/*.md",
    PROJ + "/solutions/**/*.md",
    PROJ + "/solutions/**/*.py",
    "~/ctf/*.py",
]
TEXT_EXT = {".md", ".py", ".txt", ".sh", ".js", ".mjs"}

def has_fts5():
    try:
        sqlite3.connect(":memory:").execute("CREATE VIRTUAL TABLE t USING fts5(x)")
        return True
    except sqlite3.OperationalError:
        return False

def iter_files():
    seen = set()
    for g in SRC_GLOBS:
        for p in glob.glob(g, recursive=True):
            if p in seen or not os.path.isfile(p):
                continue
            if os.path.splitext(p)[1].lower() not in TEXT_EXT:
                continue
            if os.path.getsize(p) > 1_000_000:
                continue
            seen.add(p)
            yield p

def reindex():
    fts = has_fts5()
    con = sqlite3.connect(DB); cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS docs")
    if fts:
        cur.execute("CREATE VIRTUAL TABLE docs USING fts5(path, body)")
    else:
        cur.execute("CREATE TABLE docs(path TEXT, body TEXT)")
    n = 0
    for p in iter_files():
        try:
            body = open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        cur.execute("INSERT INTO docs(path, body) VALUES(?,?)", (p, body)); n += 1
    con.commit(); con.close()
    print("reindexed %d files -> %s  (fts5=%s)" % (n, DB, fts))

def query(terms):
    if not os.path.exists(DB):
        reindex()
    con = sqlite3.connect(DB); cur = con.cursor()
    try:
        rows = cur.execute(
            "SELECT path, snippet(docs,1,'>>','<<',' … ',12), bm25(docs) "
            "FROM docs WHERE docs MATCH ? ORDER BY bm25(docs) LIMIT 8", (terms,)
        ).fetchall()
    except sqlite3.OperationalError:
        like = "%" + terms.replace(" ", "%") + "%"
        rows = cur.execute(
            "SELECT path, substr(body,1,240), 0 FROM docs WHERE body LIKE ? LIMIT 8", (like,)
        ).fetchall()
    con.close()
    if not rows:
        print("no matches for:", terms); return
    for path, snip, rank in rows:
        name = path.replace(MEM + "/", "memory/").replace(PROJ + "/", "")
        print("### %s  (bm25=%.2f)" % (name, rank))
        print("    " + " ".join(snip.split()))
        print()

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "reindex":
        reindex()
    elif len(sys.argv) >= 3 and sys.argv[1] == "query":
        query(" ".join(sys.argv[2:]))
    else:
        print(__doc__)
