"""Rate-limit-aware wrappers around gm.GM (3 parallel agents share one token)."""
import sys, json, time
sys.path.insert(0, "~/ctf")
from gm import GM


class GMX(GM):
    def _retry(self, fn, *a):
        d = 1.5
        for _ in range(10):
            r = fn(*a)
            if isinstance(r, dict) and r.get("error") == "rate_limited":
                time.sleep(d); d = min(d * 1.6, 10); continue
            if isinstance(r, (bytes, bytearray)) and r[:1] == b"{" and len(r) < 400 and b"rate_limited" in r:
                time.sleep(d); d = min(d * 1.6, 10); continue
            return r
        return r

    def post(self, body):
        return self._retry(super().post, body)

    def status(self, ch):
        return self._retry(super().status, ch)

    def artifact(self, ch, delivery=None):
        return self._retry(super().artifact, ch, delivery)
