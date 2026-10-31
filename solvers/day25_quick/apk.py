"""apk.py — pure-Python APK identity parser (Day 21 metadata 'Package Deal').
 * axml(): binary AndroidManifest.xml (AXML) -> element tree (string pool UTF-8/UTF-16, resource-map attr-id fallback names,
   typed values string/int/hex/bool/reference/float).
 * manifest(): package / versionCode / versionName / uses-sdk / application label / activities / permissions ...
 * signers(): X.509 certs from v1 META-INF/*.RSA|DSA|EC (PKCS#7) and from the APK Signing Block (v2 0x7109871a / v3 0xf05368c0),
   with md5/sha1/sha256 fingerprints (lowercase hex, no colons), subject/issuer, serial.
 * field(b, snake): generic `apk.<snake>` resolver with aliases.   usage: apk.py <file.apk> prints everything.
Nothing is executed; the APK is only parsed as a zip."""
import io, re, struct, zipfile, hashlib, json

cj = lambda x: json.dumps(x, separators=(",", ":"))

ATTR_IDS = {0x01010000: "theme", 0x01010001: "label", 0x01010002: "icon", 0x01010003: "name", 0x0101000f: "debuggable",
            0x01010010: "exported", 0x0101020c: "minSdkVersion", 0x0101021b: "versionCode", 0x0101021c: "versionName",
            0x01010270: "targetSdkVersion", 0x0101026c: "allowBackup", 0x01010572: "compileSdkVersion",
            0x01010573: "compileSdkVersionCodename", 0x0101021d: "maxSdkVersion", 0x0101027f: "authorities",
            0x01010006: "permission", 0x01010007: "process", 0x0101000e: "enabled", 0x01010204: "scheme", 0x01010028: "host",
            0x01010027: "port", 0x0101002a: "path", 0x01010026: "mimeType", 0x01010029: "pathPrefix", 0x0101002b: "pathPattern"}


def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
def _u32(b, o): return struct.unpack_from("<I", b, o)[0]


def _pool(b, off):
    hs = _u16(b, off + 2); size = _u32(b, off + 4)
    n = _u32(b, off + 8); flags = _u32(b, off + 16); ss = _u32(b, off + 20)
    utf8 = bool(flags & 0x100)
    base = off + ss
    out = []
    for i in range(n):
        p = base + _u32(b, off + hs + 4 * i)
        try:
            if utf8:
                l = b[p]; p += 1
                if l & 0x80: p += 1
                bl = b[p]; p += 1
                if bl & 0x80: bl = ((bl & 0x7f) << 8) | b[p]; p += 1
                out.append(b[p:p + bl].decode("utf-8", "replace"))
            else:
                l = _u16(b, p); p += 2
                if l & 0x8000: l = ((l & 0x7fff) << 16) | _u16(b, p); p += 2
                out.append(b[p:p + 2 * l].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out, off + size


def _typed(strs, dt, data, raw):
    if dt == 0x03:
        return strs[data] if data < len(strs) else (strs[raw] if raw < len(strs) else "")
    if dt == 0x10: return data if data < 0x80000000 else data - 0x100000000
    if dt == 0x11: return "0x%x" % data
    if dt == 0x12: return bool(data)
    if dt == 0x01: return "@0x%08x" % data
    if dt == 0x02: return "?0x%08x" % data
    if dt == 0x04: return struct.unpack("<f", struct.pack("<I", data))[0]
    if raw < len(strs): return strs[raw]
    return data


def axml(b):
    """-> (root element, all elements in document order). element = {name, attrs{name:value}, children[], parent, ns}"""
    if len(b) < 8 or _u16(b, 0) != 0x0003:
        raise ValueError("not AXML")
    off = _u16(b, 2); end = min(len(b), _u32(b, 4))
    strs, resmap = [], []
    root = None; stack = []; elems = []
    while off + 8 <= end:
        t = _u16(b, off); hs = _u16(b, off + 2); sz = _u32(b, off + 4)
        if sz < 8: break
        if t == 0x0001:
            strs, _ = _pool(b, off)
        elif t == 0x0180:
            resmap = [_u32(b, off + hs + 4 * i) for i in range((sz - hs) // 4)]
        elif t == 0x0102:
            name = strs[_u32(b, off + 20)]
            ast = _u16(b, off + 24); asz = _u16(b, off + 26); ac = _u16(b, off + 28)
            attrs = {}
            p = off + 16 + ast
            for i in range(ac):
                ns, an, raw, vsz, res0, dt, data = struct.unpack_from("<IIIHBBI", b, p + asz * i)
                aname = strs[an] if an < len(strs) else ""
                if (not aname) and an < len(resmap):
                    aname = ATTR_IDS.get(resmap[an], "attr_0x%08x" % resmap[an])
                attrs[aname] = _typed(strs, dt, data, raw)
            el = {"name": name, "attrs": attrs, "children": [], "parent": stack[-1] if stack else None}
            if stack: stack[-1]["children"].append(el)
            else: root = root or el
            stack.append(el); elems.append(el)
        elif t == 0x0103:
            if stack: stack.pop()
        off += sz
    return root, elems


def _find(elems, name):
    return [e for e in elems if e["name"] == name]


def _qual(pkg, n):
    if n is None: return None
    n = str(n)
    if n.startswith("."): return pkg + n
    if "." not in n: return pkg + "." + n
    return n


def manifest(apk_bytes):
    z = zipfile.ZipFile(io.BytesIO(apk_bytes))
    root, elems = axml(z.read("AndroidManifest.xml"))
    m = root["attrs"]
    pkg = m.get("package", "")
    d = {"package": pkg, "versionCode": m.get("versionCode"), "versionName": m.get("versionName"),
         "compileSdkVersion": m.get("compileSdkVersion"), "compileSdkVersionCodename": m.get("compileSdkVersionCodename"),
         "platformBuildVersionCode": m.get("platformBuildVersionCode"), "platformBuildVersionName": m.get("platformBuildVersionName"),
         "installLocation": m.get("installLocation"), "sharedUserId": m.get("sharedUserId")}
    sdk = _find(elems, "uses-sdk")
    d["minSdkVersion"] = sdk[0]["attrs"].get("minSdkVersion") if sdk else None
    d["targetSdkVersion"] = sdk[0]["attrs"].get("targetSdkVersion") if sdk else None
    d["maxSdkVersion"] = sdk[0]["attrs"].get("maxSdkVersion") if sdk else None
    app = _find(elems, "application")
    a = app[0]["attrs"] if app else {}
    d["label"] = a.get("label"); d["icon"] = a.get("icon"); d["theme"] = a.get("theme")
    d["applicationName"] = _qual(pkg, a.get("name")) if a.get("name") else None
    d["debuggable"] = a.get("debuggable"); d["allowBackup"] = a.get("allowBackup")
    d["activities"] = [_qual(pkg, e["attrs"].get("name")) for e in _find(elems, "activity")]
    d["activityAliases"] = [_qual(pkg, e["attrs"].get("name")) for e in _find(elems, "activity-alias")]
    d["services"] = [_qual(pkg, e["attrs"].get("name")) for e in _find(elems, "service")]
    d["receivers"] = [_qual(pkg, e["attrs"].get("name")) for e in _find(elems, "receiver")]
    d["providers"] = [_qual(pkg, e["attrs"].get("name")) for e in _find(elems, "provider")]
    d["exportedActivities"] = [_qual(pkg, e["attrs"].get("name")) for e in _find(elems, "activity") if e["attrs"].get("exported") is True]
    d["usesPermissions"] = [e["attrs"].get("name") for e in _find(elems, "uses-permission")]
    d["permissions"] = [e["attrs"].get("name") for e in _find(elems, "permission")]
    d["usesFeatures"] = [e["attrs"].get("name") for e in _find(elems, "uses-feature")]
    launch = []
    for e in _find(elems, "activity") + _find(elems, "activity-alias"):
        for f in e["children"]:
            if f["name"] != "intent-filter": continue
            acts = [c["attrs"].get("name") for c in f["children"] if c["name"] == "action"]
            cats = [c["attrs"].get("name") for c in f["children"] if c["name"] == "category"]
            if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
                launch.append(_qual(pkg, e["attrs"].get("name")))
    d["launcherActivities"] = launch
    d["mainActivity"] = launch[0] if launch else None
    d["mainActivityLabel"] = None
    for e in _find(elems, "activity"):
        if _qual(pkg, e["attrs"].get("name")) == d["mainActivity"]:
            d["mainActivityLabel"] = e["attrs"].get("label")
    return d


# ------------------------------------------------------------------ signatures
def _x509(der):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    c = x509.load_der_x509_certificate(der)
    def cn(name):
        try:
            return name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            return None
    return {"der": der, "sha256": c.fingerprint(hashes.SHA256()).hex(), "sha1": c.fingerprint(hashes.SHA1()).hex(),
            "md5": c.fingerprint(hashes.MD5()).hex(), "subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "subject_cn": cn(c.subject), "issuer_cn": cn(c.issuer), "serial_hex": "%x" % c.serial_number,
            "serial_dec": str(c.serial_number), "not_before": c.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": c.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pubkey_sha256": hashlib.sha256(c.public_key().public_bytes(
                __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER,
                __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
            "sig_algo": c.signature_algorithm_oid._name}


def v1_signers(z):
    out = []
    from cryptography.hazmat.primitives.serialization import pkcs7
    for n in z.namelist():
        if n.upper().startswith("META-INF/") and n.upper().rsplit(".", 1)[-1] in ("RSA", "DSA", "EC"):
            try:
                for c in pkcs7.load_der_pkcs7_certificates(z.read(n)):
                    from cryptography.hazmat.primitives.serialization import Encoding
                    out.append(dict(_x509(c.public_bytes(Encoding.DER)), file=n))
            except Exception as ex:
                out.append({"file": n, "error": repr(ex)})
    return out


def signing_block(b):
    """-> {id_hex: value_bytes} of the APK Signing Block, or {}."""
    eocd = b.rfind(b"PK\x05\x06")
    if eocd < 0: return {}
    cd_off = _u32(b, eocd + 16)
    if cd_off < 24 or b[cd_off - 16:cd_off] != b"APK Sig Block 42": return {}
    size = struct.unpack_from("<Q", b, cd_off - 24)[0]
    start = cd_off - 8 - size
    if start < 0 or struct.unpack_from("<Q", b, start)[0] != size: return {}
    p = start + 8; end = cd_off - 24
    out = {}
    while p + 12 <= end:
        ln = struct.unpack_from("<Q", b, p)[0]; pid = _u32(b, p + 8)
        out["0x%08x" % pid] = b[p + 12:p + 8 + ln]
        p += 8 + ln
    return out


def _lp(b, p):
    n = _u32(b, p); return b[p + 4:p + 4 + n], p + 4 + n


def v2_signers(b):
    """certs from APK Signature Scheme v2 (0x7109871a) / v3 (0xf05368c0) blocks: [{scheme, sha256,...}]"""
    out = []
    for sid, scheme in (("0x7109871a", 2), ("0xf05368c0", 3), ("0x1b93ad61", 31)):
        blk = signing_block(b).get(sid)
        if not blk: continue
        try:
            signers, _ = _lp(blk, 0)
            p = 0
            while p + 4 <= len(signers):
                signer, p = _lp(signers, p)
                signed, _ = _lp(signer, 0)
                q = 0
                if scheme in (3, 31):
                    digests, q = _lp(signed, 0)
                    certs, q = _lp(signed, q)
                else:
                    digests, q = _lp(signed, 0)
                    certs, q = _lp(signed, q)
                r = 0
                while r + 4 <= len(certs):
                    der, r = _lp(certs, r)
                    out.append(dict(_x509(der), scheme=scheme))
        except Exception as ex:
            out.append({"scheme": scheme, "error": repr(ex)})
    return out


def info(apk_bytes):
    z = zipfile.ZipFile(io.BytesIO(apk_bytes))
    d = {"manifest": manifest(apk_bytes)}
    d["members"] = [i.filename for i in z.infolist()]
    d["member_count"] = len(d["members"])
    d["dex"] = {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)}
    d["v1"] = v1_signers(z)
    d["v2"] = v2_signers(apk_bytes)
    sb = signing_block(apk_bytes)
    d["signing_block_ids"] = sorted(sb)
    schemes = []
    if d["v1"]: schemes.append(1)
    if "0x7109871a" in sb: schemes.append(2)
    if "0xf05368c0" in sb: schemes.append(3)
    if "0x1b93ad61" in sb: schemes.append(31)
    d["schemes"] = schemes
    d["native_libs"] = [n for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")]
    d["abis"] = sorted({n.split("/")[1] for n in d["native_libs"]})
    d["sha256"] = hashlib.sha256(apk_bytes).hexdigest()
    return d


def _s(v):
    if v is None: return "none"
    if isinstance(v, bool): return "true" if v else "false"
    if isinstance(v, (list, dict)): return cj(v)
    return str(v)


def field(apk_bytes, snake):
    """apk.<snake> -> string answer (aliases cover the obvious spellings)."""
    s = snake.lower()
    i = info(apk_bytes); m = i["manifest"]
    signer = (i["v1"] or i["v2"] or [{}])[0]
    if s in ("package_name", "package", "package_id", "application_id", "manifest_package"):
        return _s(m["package"])
    if s in ("version_code", "versioncode", "manifest_version_code"): return _s(m["versionCode"])
    if s in ("version_name", "versionname", "manifest_version_name"): return _s(m["versionName"])
    if s in ("min_sdk_version", "min_sdk", "minsdkversion", "uses_sdk_min_sdk_version"): return _s(m["minSdkVersion"])
    if s in ("target_sdk_version", "target_sdk", "targetsdkversion"): return _s(m["targetSdkVersion"])
    if s in ("max_sdk_version", "max_sdk"): return _s(m["maxSdkVersion"])
    if s in ("compile_sdk_version", "compile_sdk"): return _s(m["compileSdkVersion"])
    if s in ("compile_sdk_version_codename",): return _s(m["compileSdkVersionCodename"])
    if s in ("platform_build_version_code",): return _s(m["platformBuildVersionCode"])
    if s in ("platform_build_version_name",): return _s(m["platformBuildVersionName"])
    if s in ("application_label", "app_label", "label", "app_name", "application_name_label", "product_name", "display_name",
             "manifest_application_label", "application_label_text"):
        return _s(m["label"])
    if s in ("application_class", "application_name", "application_class_name"): return _s(m["applicationName"])
    if s in ("main_activity", "launcher_activity", "launchable_activity", "main_activity_name", "launcher_activity_name",
             "launchable_activity_name", "entry_activity"):
        return _s(m["mainActivity"])
    if s in ("launcher_activities", "launchable_activities", "main_activities"): return _s(m["launcherActivities"])
    if s in ("main_activity_label", "launcher_activity_label"): return _s(m["mainActivityLabel"])
    if s in ("activities", "activity_names", "activity_name_list", "manifest_activities"): return _s(m["activities"])
    if s in ("exported_activities", "exported_activity_names"): return _s(m["exportedActivities"])
    if s in ("services", "service_names"): return _s(m["services"])
    if s in ("receivers", "receiver_names"): return _s(m["receivers"])
    if s in ("providers", "provider_names"): return _s(m["providers"])
    if s in ("uses_permissions", "permissions", "requested_permissions", "uses_permission_names", "permission_names"):
        return _s(m["usesPermissions"])
    if s in ("declared_permissions", "defined_permissions"): return _s(m["permissions"])
    if s in ("uses_features", "features"): return _s(m["usesFeatures"])
    if s in ("debuggable", "is_debuggable"): return _s(bool(m["debuggable"])) if m["debuggable"] is not None else "false"
    if s in ("allow_backup",): return _s(bool(m["allowBackup"])) if m["allowBackup"] is not None else "none"
    if s in ("shared_user_id",): return _s(m["sharedUserId"])
    if s in ("install_location",): return _s(m["installLocation"])
    toks = s.split("_")
    pool = None
    if toks and toks[0] in ("v1", "v2", "v3"):
        pool = i["v1"] if toks[0] == "v1" else i["v2"]; toks = toks[1:]
    stripped = 0
    while toks and toks[0] in ("signer", "signing", "signature", "cert", "certificate", "x509", "apk", "first", "primary"):
        toks = toks[1:]; stripped += 1
    if stripped:
        k = "_".join(toks)
        sg = (pool or [signer])[0] if pool is not None else signer
        if not sg: return "none"
        for key in ("sha256", "sha1", "md5"):
            if k in (key, key + "_fingerprint", key + "_hex", "fingerprint_" + key, key + "_digest", "digest_" + key):
                return sg.get(key, "none")
            if k in (key + "_colon", key + "_fingerprint_colon", "fingerprint_" + key + "_colon"):
                h = sg.get(key, ""); return ":".join(h[j:j + 2] for j in range(0, len(h), 2)).upper() if h else "none"
        if k in ("fingerprint", "digest"): return sg.get("sha256", "none")
        if k in ("subject", "subject_dn", "dn"): return _s(sg.get("subject"))
        if k in ("subject_cn", "cn", "common_name", "subject_common_name"): return _s(sg.get("subject_cn"))
        if k in ("issuer", "issuer_dn"): return _s(sg.get("issuer"))
        if k in ("issuer_cn", "issuer_common_name"): return _s(sg.get("issuer_cn"))
        if k in ("serial", "serial_hex", "serial_number", "serial_number_hex"): return _s(sg.get("serial_hex"))
        if k in ("serial_dec", "serial_number_dec", "serial_decimal"): return _s(sg.get("serial_dec"))
        if k in ("not_before", "valid_from"): return _s(sg.get("not_before"))
        if k in ("not_after", "valid_to", "expiry"): return _s(sg.get("not_after"))
        if k in ("pubkey_sha256", "public_key_sha256", "spki_sha256"): return _s(sg.get("pubkey_sha256"))
        if k in ("algorithm", "sig_algo", "signature_algorithm"): return _s(sg.get("sig_algo"))
        if k in ("count", "cert_count"): return str(len(i["v1"]) or len(i["v2"]))
        if k in ("file", "file_name", "filename", "block_name"): return _s(sg.get("file"))
        if k in ("schemes", "scheme_versions", "versions"): return _s(i["schemes"])
    if s in ("signature_schemes", "signature_scheme_versions", "signing_schemes", "signed_with_schemes", "apk_signature_schemes",
             "signature_versions", "signing_scheme_versions"):
        return _s(i["schemes"])
    if s in ("has_signing_block", "apk_signing_block_present", "signing_block_present"): return _s(bool(i["signing_block_ids"]))
    if s in ("v1_signed", "has_v1_signature", "jar_signed"): return _s(bool(i["v1"]))
    if s in ("v2_signed", "has_v2_signature"): return _s(2 in i["schemes"])
    if s in ("v3_signed", "has_v3_signature"): return _s(3 in i["schemes"])
    if s in ("v1_signature_file_names", "signature_files", "meta_inf_signature_files"):
        return _s([n for n in i["members"] if n.upper().startswith("META-INF/") and n.upper().rsplit(".", 1)[-1] in ("RSA", "DSA", "EC", "SF")])
    if s in ("classes_dex_sha256", "dex_sha256", "primary_dex_sha256", "classes_dex_sha256_hex"):
        return _s(i["dex"].get("classes.dex"))
    if s in ("dex_sha256_set", "dex_digests"): return _s(i["dex"])
    if s in ("dex_count", "dex_file_count", "classes_dex_count"): return str(len(i["dex"]))
    if s in ("dex_names", "dex_files", "dex_file_names"): return _s(sorted(i["dex"]))
    if s in ("member_names", "entry_names", "zip_member_names", "entries", "file_names"): return _s(i["members"])
    if s in ("member_count", "entry_count", "zip_entry_count"): return str(i["member_count"])
    if s in ("native_libs", "native_libraries", "so_files"): return _s(i["native_libs"])
    if s in ("abis", "native_abis", "supported_abis"): return _s(i["abis"])
    if s in ("has_native_libs", "has_native_code"): return _s(bool(i["native_libs"]))
    if s in ("sha256", "file_sha256"): return i["sha256"]
    if s in ("has_resources_arsc", "resources_present"): return _s("resources.arsc" in i["members"])
    raise KeyError("unknown apk field %s" % snake)


if __name__ == "__main__":
    import sys
    for f in sys.argv[1:]:
        b = open(f, "rb").read()
        i = info(b)
        for c in i["v1"] + i["v2"]:
            c.pop("der", None)
        print(f); print(json.dumps(i, indent=1, default=str))
