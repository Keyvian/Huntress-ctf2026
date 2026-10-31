"""X.509 certificate field extractor (Day-29 'Trust Issues'). Accepts PEM (first CERTIFICATE block, or every block via
certs()) or raw DER. Fingerprints are hashes of the DER encoding (what openssl x509 -fingerprint prints, minus colons).
usage: x509.py <file> [field ...]"""
import sys, re, base64, hashlib, json

PEM_RE = re.compile(rb"-----BEGIN (?:TRUSTED |X509 )?CERTIFICATE-----\s*(.+?)\s*-----END (?:TRUSTED |X509 )?CERTIFICATE-----",
                    re.S)


def ders(b):
    out = [base64.b64decode(re.sub(rb"\s+", b"", m.group(1))) for m in PEM_RE.finditer(b)]
    if not out and b[:1] == b"\x30":
        out = [b]
    return out


def der(b):
    d = ders(b)
    if not d:
        raise ValueError("no certificate")
    return d[0]


def _cert(b):
    from cryptography import x509
    return x509.load_der_x509_certificate(der(b))


def _name_attr(name, oid):
    v = name.get_attributes_for_oid(oid)
    return v[0].value if v else None


def field(b, f):
    d = der(b)
    if f in ("sha256_fingerprint", "fingerprint_sha256", "sha256"):
        return hashlib.sha256(d).hexdigest()
    if f in ("sha1_fingerprint", "fingerprint_sha1", "sha1"):
        return hashlib.sha1(d).hexdigest()
    if f in ("md5_fingerprint", "fingerprint_md5", "md5"):
        return hashlib.md5(d).hexdigest()
    if f == "certificate_count":
        return len(ders(b))
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    c = _cert(b)
    if f in ("serial", "serial_number", "serial_hex"):
        return format(c.serial_number, "x")
    if f == "serial_decimal":
        return str(c.serial_number)
    if f in ("subject_cn", "subject_common_name"):
        return _name_attr(c.subject, NameOID.COMMON_NAME)
    if f in ("issuer_cn", "issuer_common_name"):
        return _name_attr(c.issuer, NameOID.COMMON_NAME)
    if f in ("subject", "subject_dn"):
        return c.subject.rfc4514_string()
    if f in ("issuer", "issuer_dn"):
        return c.issuer.rfc4514_string()
    if f in ("subject_o", "subject_organization"):
        return _name_attr(c.subject, NameOID.ORGANIZATION_NAME)
    if f in ("issuer_o", "issuer_organization"):
        return _name_attr(c.issuer, NameOID.ORGANIZATION_NAME)
    if f in ("not_before", "valid_from"):
        return c.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    if f in ("not_after", "valid_to"):
        return c.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    if f == "self_signed":
        return c.subject == c.issuer
    if f == "version":
        return c.version.value + 1
    if f in ("signature_algorithm", "signature_algorithm_oid"):
        return c.signature_algorithm_oid.dotted_string if f.endswith("oid") else c.signature_algorithm_oid._name
    if f in ("san_dns", "subject_alt_names", "san"):
        try:
            e = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            return e.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []
    if f in ("is_ca", "basic_constraints_ca"):
        try:
            return c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
        except x509.ExtensionNotFound:
            return False
    if f in ("subject_key_identifier", "ski"):
        try:
            return c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest.hex()
        except x509.ExtensionNotFound:
            return None
    if f in ("spki_sha256", "public_key_sha256"):
        from cryptography.hazmat.primitives import serialization
        return hashlib.sha256(c.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    raise KeyError("unknown x509 field " + f)


def info(b):
    out = {}
    for f in ("sha256_fingerprint", "sha1_fingerprint", "serial", "subject", "issuer", "not_before", "not_after",
              "self_signed", "signature_algorithm", "san_dns", "is_ca", "subject_key_identifier", "certificate_count"):
        try:
            out[f] = field(b, f)
        except Exception as ex:
            out[f] = "ERR " + repr(ex)
    return out


if __name__ == "__main__":
    b = open(sys.argv[1], "rb").read()
    if len(sys.argv) > 2:
        for f in sys.argv[2:]:
            print(f, field(b, f))
    else:
        print(json.dumps(info(b), indent=1, default=str))
