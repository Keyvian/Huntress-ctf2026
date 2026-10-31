"""Day-30 metadata 'Seeing Double': relation.* fields of a cluster zip (artifacts/* + optionally delivery-manifest.json).
Two shapes seen: single_solve = 5 families of 6 with a manifest (id = filename stem); time_trial = anonymous extensionless names
(`artifacts/drift-74`), no manifest, duplicate groups mixed with singletons, some of which are one-byte near-duplicates
(`ErrorActjonPreference`, or a flipped byte inside a nested zip, which breaks that inner member's CRC).
Groups are computed from the member bytes, never from any manifest size/sha256 claim. A group needs >= 2 members.
Answer shape proven on single_solve: nested arrays of ids (filenames with an extension are graded incorrect).
usage: rel30.py <cluster.zip>"""
import sys, io, json, zipfile, hashlib, collections

MANIFEST = "delivery-manifest.json"


def members(b):
    """-> ordered [(path, bytes)] of every non-directory member except the delivery manifest"""
    z = zipfile.ZipFile(io.BytesIO(b))
    return [(i.filename, z.read(i.filename)) for i in z.infolist() if not i.is_dir() and i.filename != MANIFEST]


def manifest(b):
    """-> parsed manifest dict, or None when the cluster ships without one"""
    z = zipfile.ZipFile(io.BytesIO(b))
    return json.loads(z.read(MANIFEST)) if MANIFEST in z.namelist() else None


def ids(b):
    """-> path -> id function; a member no manifest lists falls back to its filename stem"""
    m = {a["path"]: a["id"] for a in (manifest(b) or {}).get("artifacts", [])}
    return lambda p: m.get(p) or p.rsplit("/", 1)[-1].rsplit(".", 1)[0]


def groups(b, key=None, sort=True, singletons=False):
    key = key or ids(b)
    by = collections.defaultdict(list)
    for p, d in members(b):
        by[hashlib.sha256(d).hexdigest()].append(key(p))
    gs = [v for v in by.values() if singletons or len(v) > 1]
    return sorted(sorted(v) for v in gs) if sort else gs


def check_manifest(b):
    """-> list of mismatches between the manifest's claims and the delivered bytes ([] without a manifest)"""
    m = manifest(b)
    if m is None:
        return []
    z = zipfile.ZipFile(io.BytesIO(b))
    names = set(z.namelist())
    out = []
    claimed = set()
    for a in m["artifacts"]:
        claimed.add(a["path"])
        if a["path"] not in names:
            out.append((a["id"], "MISSING"))
            continue
        d = z.read(a["path"])
        if hashlib.sha256(d).hexdigest() != a["sha256"] or len(d) != a["size_bytes"]:
            out.append((a["id"], "CLAIM", a["sha256"][:12], hashlib.sha256(d).hexdigest()[:12]))
    extra = names - claimed - {MANIFEST}
    if extra:
        out.append(("EXTRA", sorted(extra)))
    return out


def field(b, name):
    if name == "identical_sha256_groups":
        return groups(b)
    raise KeyError("unknown field relation." + name)


if __name__ == "__main__":
    b = open(sys.argv[1], "rb").read()
    print(json.dumps(groups(b), separators=(",", ":")))
    print("manifest mismatches:", check_manifest(b))
