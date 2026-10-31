"""Day-15 OOXML (docx/xlsx/pptx) relationship + property parser for metadata 'A Word to the Wise'.
OOXML(b).info -> dict of snake_case fields; relationships walked over every *.rels part in archive order, each in document order."""
import io, re, json, zipfile
import xml.etree.ElementTree as ET

NS_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"


def _local(tag):
    return tag.split("}", 1)[-1]


def _resolve(rels_part, target):
    """internal target -> absolute part name (no leading slash), relative to the rels' source part dir."""
    if target.startswith("/"):
        return target.lstrip("/")
    src_dir = rels_part.rsplit("_rels/", 1)[0]  # 'word/_rels/document.xml.rels' -> 'word/'
    parts = (src_dir + target).split("/")
    out = []
    for p in parts:
        if p == "..":
            if out: out.pop()
        elif p not in (".", ""):
            out.append(p)
    return "/".join(out)


class OOXML:
    def __init__(self, b):
        self.z = zipfile.ZipFile(io.BytesIO(b))
        self.names = self.z.namelist()
        self.rels = []  # dicts: part, id, type, type_short, target, mode, resolved
        for n in self.names:
            if not n.endswith(".rels"):
                continue
            try:
                root = ET.fromstring(self.z.read(n))
            except Exception:
                continue
            for r in root.iter(NS_REL + "Relationship"):
                t = r.get("Target") or ""
                mode = r.get("TargetMode") or "Internal"
                ty = r.get("Type") or ""
                self.rels.append(dict(part=n, id=r.get("Id"), type=ty, type_short=ty.rsplit("/", 1)[-1], target=t, mode=mode,
                                      resolved=t if mode.lower() == "external" else _resolve(n, t)))
        self.info = self._info()

    def xml(self, name):
        try:
            return ET.fromstring(self.z.read(name))
        except Exception:
            return None

    def _props(self, name):
        d = {}
        r = self.xml(name)
        if r is None:
            return d
        for e in r:
            d[_local(e.tag)] = (e.text or "").strip()
        return d

    def _text(self):
        out = []
        for n in self.names:
            if re.match(r"(word/document|word/header\d*|word/footer\d*|xl/sharedStrings|ppt/slides/slide\d+)\.xml$", n):
                r = self.xml(n)
                if r is None: continue
                for e in r.iter():
                    if _local(e.tag) == "t" and e.text:
                        out.append(e.text)
        return out

    def _info(self):
        ext = [r for r in self.rels if r["mode"].lower() == "external"]
        intr = [r for r in self.rels if r["mode"].lower() != "external"]
        core = self._props("docProps/core.xml")
        app = self._props("docProps/app.xml")
        # day-15 single_solve: document order was INCORRECT, sorted order CORRECT -> list answers are sorted(set(...))
        i = {
            "external_relationship_targets": sorted(set(r["target"] for r in ext)),
            "internal_relationship_targets": sorted(set(r["target"] for r in intr)),
            "external_relationship_targets_docorder": [r["target"] for r in ext],
            "internal_relationship_targets_docorder": [r["target"] for r in intr],
            "internal_relationship_targets_resolved": sorted(set(r["resolved"] for r in intr)),
            "external_relationship_count": len(ext),
            "internal_relationship_count": len(intr),
            "relationship_count": len(self.rels),
            "external_relationship_ids": [r["id"] for r in ext],
            "external_relationship_types": [r["type"] for r in ext],
            "external_relationship_type_names": [r["type_short"] for r in ext],
            "relationship_parts": [n for n in self.names if n.endswith(".rels")],
            "parts": list(self.names),
            "part_count": len(self.names),
            "text": self._text(),
        }
        for k, v in core.items():
            i["core_" + re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower()] = v
        for k, v in app.items():
            i["app_" + re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower()] = v
        tok = [re.search(r"token:\s*(\S+)", t) for t in i["text"]]
        tok = [m.group(1) for m in tok if m]
        i["document_token"] = tok[0] if tok else "none"
        # external rels by short type (hyperlink / attachedTemplate / oleObject / frame / image ...)
        for r in ext:
            kk = "external_" + re.sub(r"(?<!^)(?=[A-Z])", "_", r["type_short"]).lower() + "_targets"
            i[kk] = sorted(set(i.get(kk, []) + [r["target"]]))
        tpl = [r["target"] for r in self.rels if r["type_short"] == "attachedTemplate"]
        i["attached_template_target"] = tpl[0] if tpl else "none"
        return i

    def dump(self):
        return json.dumps({"rels": self.rels, "info": {k: v for k, v in self.info.items() if k != "text"}}, indent=1)


def jcompact(v):
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


if __name__ == "__main__":
    import sys
    for f in sys.argv[1:]:
        print("==", f)
        print(OOXML(open(f, "rb").read()).dump())
