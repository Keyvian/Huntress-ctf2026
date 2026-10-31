"""Day-22 metadata 'Main Character Energy': jar.<field> resolver for Java archives (pure Python, nothing executed).
Manifest attributes are parsed per the JAR spec (72-byte line wrapping: continuation lines start with a single space;
sections split on blank lines; only the MAIN section is used for attribute lookups). Snake-case field names map to
manifest headers (main_class -> Main-Class, start_class -> Start-Class, launcher_agent_class -> Launcher-Agent-Class ...).
Computed fields: runnable / is_runnable / executable (Main-Class present AND its .class exists in the jar, or a
Spring-Boot-style launcher + Start-Class), entry_point / entry_class / execution_begins (the class that really runs:
Start-Class when Main-Class is a known launcher, else Main-Class), main_class_exists, class_count, nested_jar_count,
nested_jars, entry_count, has_manifest, class_path, multi_release ...  Missing -> "none".
usage: jar.py <file.jar>   prints the whole record."""
import io, re, sys, zipfile, hashlib, struct

LAUNCHERS = ("org.springframework.boot.loader.JarLauncher", "org.springframework.boot.loader.WarLauncher",
             "org.springframework.boot.loader.PropertiesLauncher", "org.springframework.boot.loader.launch.JarLauncher",
             "org.springframework.boot.loader.launch.WarLauncher", "org.springframework.boot.loader.launch.PropertiesLauncher",
             "org.eclipse.jdt.internal.jarinjarloader.JarRsrcLoader", "com.simontuffs.onejar.Boot",
             "org.apache.maven.cli.MavenCli", "io.quarkus.bootstrap.runner.QuarkusEntryPoint")
LAUNCHER_START_ATTR = ("Start-Class", "Rsrc-Main-Class", "One-Jar-Main-Class", "Launcher-Main-Class", "Boot-Class",
                       "X-Main-Class", "Real-Main-Class", "Application-Class", "Entry-Class")


def parse_manifest(text):
    """-> (main_attrs dict (ordered, case-preserving keys), [(name, attrs)...] per-entry sections)."""
    text = text.decode("utf-8", "replace") if isinstance(text, (bytes, bytearray)) else text
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # join continuations
    joined = []
    for ln in lines:
        if ln.startswith(" ") and joined:
            joined[-1] += ln[1:]
        else:
            joined.append(ln)
    sections, cur = [], {}
    for ln in joined:
        if ln.strip() == "":
            if cur:
                sections.append(cur); cur = {}
            continue
        if ":" in ln:
            k, v = ln.split(":", 1)
            k = k.strip(); v = v.strip()
            if k in cur:
                cur[k] += " " + v
            else:
                cur[k] = v
    if cur:
        sections.append(cur)
    main = sections[0] if sections and not sections[0].get("Name") else {}
    entries = [(s.get("Name"), s) for s in sections if s.get("Name")]
    return main, entries


def _ci(d, key):
    """case-insensitive attribute lookup"""
    kl = key.lower()
    for k, v in d.items():
        if k.lower() == kl:
            return v
    return None


def header_for(snake):
    """main_class -> Main-Class ; launcher_agent_class -> Launcher-Agent-Class ; x_comment -> X-Comment"""
    parts = snake.split("_")
    return "-".join(p[:1].upper() + p[1:] for p in parts)


def info(b):
    z = zipfile.ZipFile(io.BytesIO(b))
    infos = z.infolist()
    names = [i.filename for i in infos]
    man_name = next((n for n in names if n.upper() == "META-INF/MANIFEST.MF"), None)
    main, entries = ({}, [])
    if man_name:
        main, entries = parse_manifest(z.read(man_name))
    classes = [n for n in names if n.endswith(".class")]
    nested = [n for n in names if n.lower().endswith((".jar", ".war", ".ear", ".zip"))]
    mc = _ci(main, "Main-Class")
    mc_path = (mc.replace(".", "/") + ".class") if mc else None
    mc_exists = bool(mc_path and mc_path in names)
    # Spring-Boot style: BOOT-INF/classes/<cls>.class
    if mc and not mc_exists:
        mc_exists = any(n.endswith("/" + mc_path) for n in names)
    start = None
    for a in LAUNCHER_START_ATTR:
        if _ci(main, a):
            start = _ci(main, a); break
    is_launcher = bool(mc and (mc in LAUNCHERS or "launcher" in mc.lower() or "loader" in mc.lower()))
    entry = (start if (is_launcher and start) else mc) or None
    entry_path = (entry.replace(".", "/") + ".class") if entry else None
    entry_exists = bool(entry_path and (entry_path in names or any(n.endswith("/" + entry_path) for n in names)))
    runnable = bool(mc) and (mc_exists or (is_launcher and bool(start)))
    # nested jar manifests
    nested_main = {}
    for n in nested:
        try:
            nb = z.read(n)
            ni = info(nb)
            nested_main[n] = ni["main_class"]
        except Exception:
            nested_main[n] = None
    return {
        "manifest": main, "entries": entries, "has_manifest": man_name is not None,
        "main_class": mc, "main_class_exists": mc_exists, "start_class": start, "is_launcher": is_launcher,
        "entry_point": entry, "entry_point_exists": entry_exists, "runnable": runnable,
        "classes": classes, "class_count": len(classes), "nested_jars": nested, "nested_jar_count": len(nested),
        "nested_main": nested_main, "names": names, "entry_count": len(infos),
        "sha256": hashlib.sha256(b).hexdigest(),
    }


def _bool(v):
    return "true" if v else "false"


def field(b, snake):
    i = info(b)
    s = snake.lower()
    man = i["manifest"]
    if s in ("main_class", "manifest_main_class"):
        return i["main_class"] or "none"
    if s in ("runnable", "is_runnable", "executable", "is_executable", "launchable"):
        return _bool(i["runnable"])
    if s in ("main_class_exists", "main_class_present", "has_main_class_file", "main_class_resolves"):
        return _bool(i["main_class_exists"])
    if s in ("has_main_class", "main_class_declared"):
        return _bool(bool(i["main_class"]))
    if s in ("entry_point", "entry_class", "execution_begins", "execution_entry", "effective_main_class",
             "real_main_class", "actual_main_class", "resolved_main_class", "launch_class", "launcher_target"):
        return i["entry_point"] or "none"
    if s in ("start_class",):
        return i["start_class"] or _ci(man, "Start-Class") or "none"
    if s in ("launcher", "launcher_class", "is_launcher"):
        return i["main_class"] if i["is_launcher"] else "none"
    if s in ("class_count", "classes", "num_classes"):
        return str(i["class_count"])
    if s in ("nested_jar_count", "nested_jars_count", "nested_count"):
        return str(i["nested_jar_count"])
    if s in ("nested_jars", "nested_jar_names", "nested"):
        import json
        return json.dumps(i["nested_jars"], separators=(",", ":")) if i["nested_jars"] else "none"
    if s in ("entry_count", "member_count", "members"):
        return str(i["entry_count"])
    if s in ("has_manifest", "manifest_present"):
        return _bool(i["has_manifest"])
    if s in ("manifest_sha256",):
        z = zipfile.ZipFile(io.BytesIO(b))
        n = next((n for n in z.namelist() if n.upper() == "META-INF/MANIFEST.MF"), None)
        return hashlib.sha256(z.read(n)).hexdigest() if n else "none"
    if s in ("sha256",):
        return i["sha256"]
    # generic manifest attribute (snake -> Header-Case, case-insensitive)
    v = _ci(man, header_for(s)) or _ci(man, s.replace("_", "-"))
    if v is None and s.startswith("manifest_"):
        v = _ci(man, header_for(s[len("manifest_"):]))
    return v if v is not None else "none"


if __name__ == "__main__":
    import json
    for p in sys.argv[1:]:
        i = info(open(p, "rb").read())
        print(json.dumps({k: v for k, v in i.items() if k != "names"}, indent=1, default=str))
