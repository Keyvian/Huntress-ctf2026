"""Game Master helper for the local WSL toolchain (credit-free public endpoint).
Import from solvers: sys.path.insert(0,"~/ctf"); from gm import GM
Token is read from the Windows-side file; never print it."""
import json, requests
BASE = "https://2026.huntress.ctf.games/"
TOKPATH = "/mnt/c/Users/<user>/.huntress-ctf/gm_token.json"

def _token():
    with open(TOKPATH) as f:
        return json.load(f)["token"]

class GM:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({"Authorization": "Bearer %s" % _token(),
                               "Content-Type": "application/json"})
    def get(self, query):                         # query e.g. "?op=list"
        return self.s.get(BASE + query, timeout=30)
    def list(self):
        return self.get("?op=list").json()
    def status(self, ch):
        return self.get("?op=status&challenge=%s" % ch).json()
    def artifact(self, ch, delivery=None):
        q = "?op=artifact&challenge=%s" % ch
        if delivery is not None:
            q += "&delivery=%s" % delivery
        return self.s.get(BASE + q, timeout=90).content
    def post(self, body):
        return self.s.post(BASE, data=json.dumps(body), timeout=60).json()
    def start(self, ch):    return self.post({"op": "start", "challenge": ch})
    def retry(self, ch):    return self.post({"op": "retry", "challenge": ch})
    def practice(self, ch): return self.post({"op": "practice", "challenge": ch})
    def submit(self, ch, answers):  # answers: {answer_id: "string", ...}
        return self.post({"op": "submit", "challenge": ch, "answers": answers})

def challenges():
    j = GM().list()
    return j if isinstance(j, list) else (j.get("challenges") or j.get("items") or [])
