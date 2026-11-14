#!/usr/bin/env python3
"""xlink - manage Xray-core configs and convert share links.

Client side (outbounds):
  xlink list   CONFIG                    list outbounds
  xlink import CONFIG LINK [--tag T]     add/replace an outbound from a share link
  xlink export CONFIG TAG                print the share link of an outbound
  xlink rm     CONFIG TAG                remove an outbound
  xlink set    CONFIG TAG KEY=VALUE...   change link fields (e.g. address=1.2.3.4 port=443)

Server side (inbound users):
  xlink users     CONFIG                         list inbound users
  xlink user-add  CONFIG INBOUND NAME [--flow F]  add a user (new UUID), print link
  xlink user-rm   CONFIG INBOUND NAME             remove a user
  xlink user-link CONFIG INBOUND NAME --host H [--pbk KEY]  print a user's link

Subscriptions (customer DB, kept apart from the xray config):
  xlink sub-user-add DB EMAIL --days N --gb G   new customer, print subscription token/URL
  xlink sub-renew    DB EMAIL --days N --gb G   new plan, same UUID and same URL
  xlink sub-topup    DB EMAIL --gb G            add reserve data, used after the quota ends
  xlink sub-disable  DB EMAIL                   switch a customer off (record kept)
  xlink sub-serve    DB CONFIG INBOUND --host H the subscription URL responder (local HTTP)
  xlink sub-list     DB                         usage, expiry and state per customer
  xlink sub-setup    CONFIG --api ADDR          enable the xray API + per-user counters
  xlink sub-sync     DB CONFIG INBOUND --api ADDR [--loop]
                                                count usage, cut off / revive users

Conversion only:
  xlink decode LINK      print the outbound JSON for a link
  xlink encode FILE|-    print the link for an outbound JSON

Supported: vless, vmess, trojan, shadowsocks; transports tcp, ws, grpc,
httpupgrade, xhttp; security none, tls, reality.

Every write makes CONFIG.bak-<timestamp> and runs `xray run -test` first
(skip with --no-test). Use `-` as CONFIG to read stdin and print to stdout.
"""
import argparse, base64, copy, json, os, shutil, subprocess, sys, time, uuid
from urllib.parse import quote, unquote, urlsplit, parse_qsl, urlencode

PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks")


def die(msg):
    print(f"xlink: {msg}", file=sys.stderr)
    sys.exit(1)


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode()


def b64e(s):
    return base64.b64encode(s.encode()).decode()


# ---------------------------------------------------------------- link -> flat
# A "flat" dict is the common middle form: protocol, address, port, id/password,
# and transport/security fields named as in v2rayN-style share links.

def parse_link(link):
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        j = json.loads(b64d(link[8:]))
        return {
            "protocol": "vmess", "address": j.get("add"), "port": int(j.get("port")),
            "id": j.get("id"), "scy": j.get("scy") or "auto",
            "type": j.get("net") or "tcp", "headerType": j.get("type") or "",
            "host": j.get("host") or "", "path": j.get("path") or "",
            "security": j.get("tls") or "none", "sni": j.get("sni") or "",
            "fp": j.get("fp") or "", "alpn": j.get("alpn") or "",
            "name": j.get("ps") or "",
        }
    if scheme == "ss":
        u = urlsplit(link)
        userinfo = unquote(u.netloc.rsplit("@", 1)[0]) if "@" in u.netloc else None
        if userinfo is None:  # legacy: ss://base64(method:pass@host:port)
            raw = b64d(u.netloc)
            userinfo, hp = raw.rsplit("@", 1)
            host, port = hp.rsplit(":", 1)
        else:
            host, port = u.hostname, u.port
            if ":" not in userinfo:
                userinfo = b64d(userinfo)
        method, password = userinfo.split(":", 1)
        return {"protocol": "shadowsocks", "address": host, "port": int(port),
                "method": method, "password": password, "type": "tcp",
                "security": "none", "name": unquote(u.fragment)}
    if scheme not in ("vless", "trojan"):
        die(f"unsupported link scheme: {scheme}")
    u = urlsplit(link)
    q = dict(parse_qsl(u.query))
    flat = {"protocol": scheme, "address": u.hostname, "port": u.port,
            "name": unquote(u.fragment)}
    flat["id" if scheme == "vless" else "password"] = unquote(u.username or "")
    flat.update(q)
    flat.setdefault("type", "tcp")
    flat.setdefault("security", "tls" if scheme == "trojan" else "none")
    return flat


# ---------------------------------------------------------------- flat -> outbound

def build_stream(f):
    net = f.get("type", "tcp")
    if net == "raw":
        net = "tcp"
    ss = {"network": net}
    sec = f.get("security", "none")
    if sec == "tls":
        t = {"serverName": f.get("sni") or f.get("host") or ""}
        if f.get("fp"): t["fingerprint"] = f["fp"]
        if f.get("alpn"): t["alpn"] = f["alpn"].split(",")
        if f.get("allowInsecure") in ("1", "true"): t["allowInsecure"] = True
        ss["security"], ss["tlsSettings"] = "tls", t
    elif sec == "reality":
        r = {"serverName": f.get("sni", ""), "fingerprint": f.get("fp") or "chrome",
             "publicKey": f.get("pbk", ""), "shortId": f.get("sid", "")}
        if f.get("spx"): r["spiderX"] = f["spx"]
        ss["security"], ss["realitySettings"] = "reality", r
    host, path = f.get("host", ""), f.get("path", "")
    if net == "ws":
        ss["wsSettings"] = {"path": path or "/", **({"host": host} if host else {})}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": f.get("serviceName") or path,
                              **({"multiMode": True} if f.get("mode") == "multi" else {})}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path or "/", **({"host": host} if host else {})}
    elif net == "xhttp":
        x = {"path": path or "/"}
        if host: x["host"] = host
        if f.get("mode"): x["mode"] = f["mode"]
        if f.get("extra"): x["extra"] = json.loads(f["extra"])
        ss["xhttpSettings"] = x
    elif net == "tcp" and f.get("headerType") == "http":
        ss["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": (path or "/").split(","), "headers": {"Host": host.split(",") if host else []}}}}
    return ss


def to_outbound(f, tag=None):
    p = f["protocol"]
    tag = tag or f.get("name") or f"{p}-{f['address']}"
    if p == "vless":
        user = {"id": f["id"], "encryption": f.get("encryption", "none")}
        if f.get("flow"): user["flow"] = f["flow"]
        settings = {"vnext": [{"address": f["address"], "port": int(f["port"]), "users": [user]}]}
    elif p == "vmess":
        settings = {"vnext": [{"address": f["address"], "port": int(f["port"]),
                               "users": [{"id": f["id"], "security": f.get("scy", "auto")}]}]}
    elif p == "trojan":
        settings = {"servers": [{"address": f["address"], "port": int(f["port"]),
                                 "password": f["password"]}]}
    else:
        settings = {"servers": [{"address": f["address"], "port": int(f["port"]),
                                 "method": f["method"], "password": f["password"]}]}
    return {"tag": tag, "protocol": p, "settings": settings, "streamSettings": build_stream(f)}


# ---------------------------------------------------------------- outbound -> flat -> link

def from_outbound(o):
    p = o.get("protocol")
    if p not in PROTOCOLS:
        die(f"outbound '{o.get('tag')}' has protocol '{p}', no share link format")
    s = o.get("settings", {})
    f = {"protocol": p, "name": o.get("tag", "")}
    if p in ("vless", "vmess"):
        v = s["vnext"][0]; u = v["users"][0]
        f.update(address=v["address"], port=v["port"], id=u["id"])
        if p == "vless":
            f["encryption"] = u.get("encryption", "none")
            if u.get("flow"): f["flow"] = u["flow"]
        else:
            f["scy"] = u.get("security", "auto")
    else:
        sv = s["servers"][0]
        f.update(address=sv["address"], port=sv["port"], password=sv["password"])
        if p == "shadowsocks": f["method"] = sv["method"]
    st = o.get("streamSettings", {})
    net = st.get("network", "tcp")
    f["type"] = "tcp" if net == "raw" else net
    sec = st.get("security", "none")
    f["security"] = sec
    if sec == "tls":
        t = st.get("tlsSettings", {})
        f["sni"] = t.get("serverName", "")
        if t.get("fingerprint"): f["fp"] = t["fingerprint"]
        if t.get("alpn"): f["alpn"] = ",".join(t["alpn"])
        if t.get("allowInsecure"): f["allowInsecure"] = "1"
    elif sec == "reality":
        r = st.get("realitySettings", {})
        f.update(sni=r.get("serverName", ""), fp=r.get("fingerprint", "chrome"),
                 pbk=r.get("publicKey", ""), sid=r.get("shortId", ""))
        if r.get("spiderX"): f["spx"] = r["spiderX"]
    tr = (st.get("wsSettings") or st.get("httpupgradeSettings") or st.get("xhttpSettings")
          or st.get("splithttpSettings") or {})
    if tr.get("path"): f["path"] = tr["path"]
    if tr.get("host"): f["host"] = tr["host"]
    if st.get("xhttpSettings", {}).get("mode"): f["mode"] = st["xhttpSettings"]["mode"]
    if st.get("xhttpSettings", {}).get("extra"):
        f["extra"] = json.dumps(st["xhttpSettings"]["extra"], separators=(",", ":"))
    if net == "grpc":
        g = st.get("grpcSettings", {})
        f["serviceName"] = g.get("serviceName", "")
        if g.get("multiMode"): f["mode"] = "multi"
    return f


QUERY_ORDER = ["encryption", "flow", "security", "sni", "fp", "pbk", "sid", "spx", "alpn",
               "allowInsecure", "type", "headerType", "host", "path", "serviceName", "mode", "extra"]


def make_link(f):
    p, name = f["protocol"], quote(f.get("name", ""))
    host = f"[{f['address']}]" if ":" in str(f["address"]) else f["address"]
    if p == "vmess":
        j = {"v": "2", "ps": f.get("name", ""), "add": f["address"], "port": str(f["port"]),
             "id": f["id"], "aid": "0", "scy": f.get("scy", "auto"), "net": f.get("type", "tcp"),
             "type": f.get("headerType", "none") or "none", "host": f.get("host", ""),
             "path": f.get("path", "") or f.get("serviceName", ""),
             "tls": "" if f.get("security") == "none" else f.get("security", ""),
             "sni": f.get("sni", ""), "fp": f.get("fp", ""), "alpn": f.get("alpn", "")}
        return "vmess://" + b64e(json.dumps(j, separators=(",", ":")))
    if p == "shadowsocks":
        ui = base64.urlsafe_b64encode(f"{f['method']}:{f['password']}".encode()).decode().rstrip("=")
        return f"ss://{ui}@{host}:{f['port']}#{name}"
    cred = f["id"] if p == "vless" else f["password"]
    q = {k: str(f[k]) for k in QUERY_ORDER if f.get(k) not in (None, "")}
    return f"{p}://{quote(cred, safe='')}@{host}:{f['port']}?{urlencode(q, quote_via=quote)}#{name}"


# ---------------------------------------------------------------- config I/O

def load(path):
    try:
        with (sys.stdin if path == "-" else open(path)) as fh:
            return json.load(fh)
    except PermissionError:
        die(f"cannot read {path} (try sudo)")
    except FileNotFoundError:
        die(f"no such file: {path}")


def save(path, cfg, args, rolling=None):
    text = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    if path == "-":
        sys.stdout.write(text); return
    tmp = f"{path}.xlink-candidate.json"
    with open(tmp, "w") as fh:
        fh.write(text)
    if not args.no_test:
        xray = shutil.which("xray") or "/usr/local/bin/xray"
        r = subprocess.run([xray, "run", "-test", "-c", tmp], capture_output=True, text=True)
        if "Configuration OK" not in r.stdout + r.stderr:
            print(r.stdout + r.stderr, file=sys.stderr)
            die(f"xray rejected the new config; left it at {tmp}, original untouched")
    bak = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    n = 1
    if rolling:  # frequent automatic writers keep one backup instead of piling them up
        bak = f"{path}.bak-{rolling}"
    while not rolling and os.path.exists(bak):
        bak = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}-{n}"; n += 1
    shutil.copy2(path, bak)
    shutil.copymode(path, tmp)
    os.replace(tmp, path)
    print(f"saved {path} (backup: {bak}); restart xray to apply", file=sys.stderr)


def find_out(cfg, tag):
    for i, o in enumerate(cfg.get("outbounds", [])):
        if o.get("tag") == tag:
            return i, o
    die(f"no outbound tagged '{tag}'")


def find_in(cfg, tag):
    for i in cfg.get("inbounds", []):
        if i.get("tag") == tag or str(i.get("port")) == tag:
            return i
    die(f"no inbound tagged '{tag}' (tag or port)")


# ---------------------------------------------------------------- commands

def cmd_list(a):
    cfg = load(a.config)
    rows = [("TAG", "PROTOCOL", "ADDRESS", "NET/SEC", "NOTE")]
    for o in cfg.get("outbounds", []):
        p = o.get("protocol", "")
        s = o.get("settings", {}); st = o.get("streamSettings", {})
        srv = (s.get("vnext") or s.get("servers") or [{}])[0]
        addr = f"{srv['address']}:{srv['port']}" if "address" in srv else "-"
        net = f"{st.get('network', 'tcp')}/{st.get('security', 'none')}" if p in PROTOCOLS else "-"
        note = []
        u = (srv.get("users") or [{}])[0]
        if u.get("flow"): note.append(u["flow"])
        if o.get("mux", {}).get("enabled"): note.append("mux")
        if st.get("sockopt", {}).get("dialerProxy"): note.append("via " + st["sockopt"]["dialerProxy"])
        rows.append((o.get("tag", "?"), p, addr, net, " ".join(note)))
    w = [max(len(r[i]) for r in rows) for i in range(5)]
    for r in rows:
        print("  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip())


def cmd_import(a):
    cfg = load(a.config)
    f = parse_link(a.link)
    ob = to_outbound(f, a.tag)
    outs = cfg.setdefault("outbounds", [])
    for i, o in enumerate(outs):
        if o.get("tag") == ob["tag"]:
            # keep local-only fields (mux, sockopt, ...) when replacing
            for k in ("mux", "proxySettings"):
                if k in o: ob[k] = o[k]
            if "sockopt" in o.get("streamSettings", {}):
                ob["streamSettings"]["sockopt"] = o["streamSettings"]["sockopt"]
            outs[i] = ob
            print(f"replaced outbound '{ob['tag']}'", file=sys.stderr)
            break
    else:
        # insert before freedom/blackhole so it does not become the default by accident
        pos = 0 if a.first else len(outs)
        if not a.first:
            for i, o in enumerate(outs):
                if o.get("protocol") in ("freedom", "blackhole", "dns"):
                    pos = i; break
        outs.insert(pos, ob)
        print(f"added outbound '{ob['tag']}'", file=sys.stderr)
    save(a.config, cfg, a)


def cmd_export(a):
    _, o = find_out(load(a.config), a.tag)
    print(make_link(from_outbound(o)))


def cmd_rm(a):
    cfg = load(a.config)
    i, _ = find_out(cfg, a.tag)
    del cfg["outbounds"][i]
    save(a.config, cfg, a)


def cmd_set(a):
    cfg = load(a.config)
    i, o = find_out(cfg, a.tag)
    f = from_outbound(o)
    for kv in a.pairs:
        k, _, v = kv.partition("=")
        if v == "": f.pop(k, None)
        else: f[k] = v
    new = to_outbound(f, o["tag"])
    for k, v in o.items():  # keep fields xlink does not model
        if k not in new: new[k] = v
    if "sockopt" in o.get("streamSettings", {}):
        new["streamSettings"]["sockopt"] = o["streamSettings"]["sockopt"]
    cfg["outbounds"][i] = new
    save(a.config, cfg, a)


def cmd_users(a):
    cfg = load(a.config)
    for ib in cfg.get("inbounds", []):
        cl = ib.get("settings", {}).get("clients")
        if cl is None: continue
        st = ib.get("streamSettings", {})
        print(f"{ib.get('tag', '?')}  port {ib.get('port')}  {ib.get('protocol')}  "
              f"{st.get('network', 'tcp')}/{st.get('security', 'none')}")
        for c in cl:
            print(f"    {c.get('email', '-'):20} {c.get('id') or c.get('password', '')}  {c.get('flow', '')}")


def inbound_link(ib, c, host, pbk, name):
    st = ib.get("streamSettings", {})
    p = ib["protocol"]
    f = {"protocol": p, "address": host, "port": ib["port"], "name": name,
         "type": st.get("network", "tcp"), "security": st.get("security", "none")}
    if p in ("vless", "vmess"): f["id"] = c["id"]
    else: f["password"] = c["password"]
    if p == "shadowsocks": f["method"] = ib["settings"].get("method") or c.get("method")
    if c.get("flow"): f["flow"] = c["flow"]
    if p == "vless": f["encryption"] = "none"
    if f["security"] == "reality":
        r = st["realitySettings"]
        if not pbk:
            die("reality inbound: pass --pbk (public key; `xray x25519 -i <privateKey>` prints it)")
        f.update(sni=r["serverNames"][0], fp="chrome", pbk=pbk,
                 sid=next((s for s in r.get("shortIds", []) if s), ""))
    elif f["security"] == "tls":
        f["sni"] = st.get("tlsSettings", {}).get("serverName", host)
    tr = st.get("wsSettings") or st.get("httpupgradeSettings") or st.get("xhttpSettings") or {}
    if tr.get("path"): f["path"] = tr["path"]
    if tr.get("host"): f["host"] = tr["host"]
    if st.get("grpcSettings"): f["serviceName"] = st["grpcSettings"].get("serviceName", "")
    return make_link(f)


def pbk_from(ib, given):
    if given: return given
    r = ib.get("streamSettings", {}).get("realitySettings")
    if not r or not r.get("privateKey"): return None
    xray = shutil.which("xray") or "/usr/local/bin/xray"
    try:
        out = subprocess.run([xray, "x25519", "-i", r["privateKey"]], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None
    for line in out.splitlines():
        k, _, v = line.partition(":")
        k = k.strip().lower()
        # "Public key" (old xray), "Password (PublicKey)" (26.x)
        if k == "public key" or k.startswith("password"):
            return v.strip()
    return None


def cmd_user_add(a):
    cfg = load(a.config)
    ib = find_in(cfg, a.inbound)
    cl = ib["settings"]["clients"]
    if any(c.get("email") == a.name for c in cl): die(f"user '{a.name}' already exists")
    c = {"email": a.name}
    if ib["protocol"] in ("vless", "vmess"): c["id"] = str(uuid.uuid4())
    else: c["password"] = base64.b64encode(os.urandom(16)).decode()
    if a.flow: c["flow"] = a.flow
    cl.append(c)
    save(a.config, cfg, a)
    if a.host:
        print(inbound_link(ib, c, a.host, pbk_from(ib, a.pbk), a.name))


def cmd_user_rm(a):
    cfg = load(a.config)
    ib = find_in(cfg, a.inbound)
    cl = ib["settings"]["clients"]
    n = len(cl)
    ib["settings"]["clients"] = [c for c in cl if c.get("email") != a.name]
    if len(ib["settings"]["clients"]) == n: die(f"no user '{a.name}'")
    save(a.config, cfg, a)


def cmd_user_link(a):
    ib = find_in(load(a.config), a.inbound)
    for c in ib["settings"]["clients"]:
        if c.get("email") == a.name:
            print(inbound_link(ib, c, a.host, pbk_from(ib, a.pbk), a.label or a.name)); return
    die(f"no user '{a.name}'")


# ---------------------------------------------------------------- subscriptions
# A users DB (JSON) is the source of truth for paying customers: permanent UUID,
# permanent subscription token, plan history, usage. The live xray config is
# derived from it; a record is never deleted, only flagged inactive.

GB = 1024 ** 3


def db_load(path):
    if not os.path.exists(path):
        return {"schema": 1, "users": []}
    with open(path) as fh:
        db = json.load(fh)
    if db.get("schema") != 1: die(f"{path}: unsupported schema {db.get('schema')!r}")
    return db


def db_save(path, db):
    tmp = f"{path}.tmp"
    # Holds UUIDs and tokens: private by default; an existing file keeps its mode
    # (e.g. 0640 so a non-root sub-serve can read it through its group).
    mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o600
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(db, indent=2, ensure_ascii=False) + "\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class db_lock:
    """Exclusive lock so a renew and a sync never overwrite each other."""
    def __init__(self, path): self.path = path + ".lock"
    def __enter__(self):
        import fcntl
        self.fh = open(self.path, "w")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
    def __exit__(self, *exc):
        self.fh.close()


def db_find(db, email):
    return next((u for u in db["users"] if u["email"] == email), None)


def plan_expiry(plan):
    y, m, d = map(int, plan["start"].split("-"))
    return time.strftime("%Y-%m-%d", time.gmtime(time.mktime((y, m, d + plan["days"], 12, 0, 0, 0, 0, -1))))


def allowance(u):
    """Bytes the user may use now: the plan's quota plus the prepaid reserve."""
    return int(u["plans"][-1]["quota_gb"] * GB) + u.get("reserve_bytes", 0)


def order_owner(db, order):
    for u in db["users"]:
        if any(x.get("order") == order for x in u["plans"] + u.get("topups", [])):
            return u
    return None


def user_state(u, today):
    """ok | disabled | expired | over-quota (the reason a user should be off)."""
    if not u["plans"]: return "disabled"
    p = u["plans"][-1]
    if today >= plan_expiry(p): return "expired"
    if u["used_bytes"] >= allowance(u): return "over-quota"
    return "ok" if u["active"] else "disabled"


def db_grant(db, email, days, gb, today, create, order=None, note=None):
    """Give EMAIL a fresh plan. Returns (user, changed).

    Idempotent per ORDER: replaying the same order id (a retried payment
    webhook, a repeated manual command) changes nothing.
    """
    if days <= 0 or gb <= 0: die("--days and --gb must be positive")
    u = db_find(db, email)
    if order and order_owner(db, order):
        if order_owner(db, order) is not u: die(f"order '{order}' already belongs to another user")
        return u, False
    if create:
        if u: die(f"user '{email}' already exists (use sub-renew)")
        u = {"email": email, "uuid": str(uuid.uuid4()), "token": os.urandom(16).hex(),
             "created": today, "plans": [], "used_bytes": 0, "active": True, "note": ""}
        db["users"].append(u)
    elif not u:
        die(f"no user '{email}' (use sub-user-add)")
    if u["plans"]:  # what the old plan overran was paid from the reserve
        over = u["used_bytes"] - int(u["plans"][-1]["quota_gb"] * GB)
        u["reserve_bytes"] = max(0, u.get("reserve_bytes", 0) - max(0, over))
    plan = {"start": today, "days": days, "quota_gb": gb}
    if order: plan["order"] = order
    u["plans"].append(plan)
    u["used_bytes"] = 0
    u["active"] = True
    if note is not None: u["note"] = note
    return u, True


def db_topup(db, email, gb, today, order=None):
    """Add GB to EMAIL's reserve: spent only after a plan's quota runs out,
    and carried over renewals. Does not extend the expiry date."""
    if gb <= 0: die("--gb must be positive")
    u = db_find(db, email) or die(f"no user '{email}'")
    if order and order_owner(db, order):
        if order_owner(db, order) is not u: die(f"order '{order}' already belongs to another user")
        return u, False
    t = {"date": today, "gb": gb}
    if order: t["order"] = order
    u.setdefault("topups", []).append(t)
    u["reserve_bytes"] = u.get("reserve_bytes", 0) + int(gb * GB)
    return u, True


def reserve_left(u):
    """Reserve not yet eaten by the current plan's overrun."""
    over = u["used_bytes"] - int(u["plans"][-1]["quota_gb"] * GB) if u["plans"] else 0
    return max(0, u.get("reserve_bytes", 0) - max(0, over))


def cmd_sub_topup(a):
    with db_lock(a.db):
        db = db_load(a.db)
        u, changed = db_topup(db, a.email, a.gb, time.strftime("%Y-%m-%d"), a.order)
        if changed: db_save(a.db, db)
    print(f"{'added' if changed else 'unchanged (order already applied)'}: {u['email']}  "
          f"reserve {reserve_left(u) / GB:.2f} GB", file=sys.stderr)


def cmd_sub_disable(a):
    """Switch a customer off by hand; the record stays, sub-renew revives it."""
    with db_lock(a.db):
        db = db_load(a.db)
        u = db_find(db, a.email) or die(f"no user '{a.email}'")
        u["active"] = False
        db_save(a.db, db)


def sub_url(base, u):
    return f"{base.rstrip('/')}/s/{u['token']}" if base else u["token"]


def cmd_sub_grant(a):
    with db_lock(a.db):
        db = db_load(a.db)
        u, changed = db_grant(db, a.email, a.days, a.gb, time.strftime("%Y-%m-%d"),
                              create=a.cmd == "sub-user-add", order=a.order, note=a.note)
        if changed: db_save(a.db, db)
    p = u["plans"][-1]
    print(f"{'granted' if changed else 'unchanged (order already applied)'}: {u['email']}  "
          f"{p['quota_gb']:g} GB until {plan_expiry(p)}", file=sys.stderr)
    print(sub_url(a.base_url, u))


def cmd_sub_list(a):
    db = db_load(a.db)
    today = time.strftime("%Y-%m-%d")
    rows = [("EMAIL", "USED/QUOTA GB", "RESERVE GB", "EXPIRES", "STATE", "NOTE")]
    for u in db["users"]:
        p = u["plans"][-1] if u["plans"] else None
        rows.append((u["email"],
                     f"{u['used_bytes'] / GB:.2f}/{p['quota_gb']:g}" if p else "-",
                     f"{reserve_left(u) / GB:.2f}",
                     plan_expiry(p) if p else "-", user_state(u, today), u.get("note", "")))
    w = [max(len(r[i]) for r in rows) for i in range(6)]
    for r in rows:
        print("  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip())


def xray_api(server, *args):
    xray = shutil.which("xray") or "/usr/local/bin/xray"
    r = subprocess.run([xray, "api", args[0], f"--server={server}", *args[1:]],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die(f"xray api {args[0]} failed: {(r.stderr or r.stdout).strip()}")
    return r.stdout


def parse_stats(text):
    """statsquery JSON -> {email: bytes} (uplink + downlink)."""
    out = {}
    for s in (json.loads(text) if text.strip() else {}).get("stat", []):
        parts = s.get("name", "").split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            out[parts[1]] = out.get(parts[1], 0) + int(s.get("value", 0))
    return out


def apply_usage(db, usage):
    for u in db["users"]:
        u["used_bytes"] += usage.get(u["email"], 0)


def sync_clients(ib, db, today, flow):
    """Make the inbound's clients match the DB. Returns (added, removed) clients.

    Only clients whose email is in the DB are managed; anything else in the
    inbound is left alone.
    """
    cl = ib["settings"].setdefault("clients", [])
    want = {u["email"]: u for u in db["users"] if user_state(u, today) == "ok"}
    known = {u["email"] for u in db["users"]}
    removed = [c for c in cl if c.get("email") in known and c["email"] not in want]
    have = {c.get("email") for c in cl}
    added = []
    for email, u in want.items():
        if email not in have:
            c = {"email": email, "id": u["uuid"]}
            if flow: c["flow"] = flow
            added.append(c)
    ib["settings"]["clients"] = [c for c in cl if c not in removed] + added
    return added, removed


def next_interval(db, today, max_mbps, lo, hi):
    """Seconds until the next poll: short when someone could run out soon.

    Assumes nobody moves data faster than MAX_MBPS, and polls at half the
    time the closest user would need to exhaust the quota at that speed.
    """
    left = [allowance(u) - u["used_bytes"]
            for u in db["users"] if user_state(u, today) == "ok"]
    if not left: return hi
    return max(lo, min(hi, min(left) / (max_mbps * 125000) / 2))


def online_ips(server, email):
    """Client IPs a user is connected from right now (needs statsUserOnline)."""
    try:
        data = json.loads(xray_api(server, "statsonlineiplist", "-email", email) or "{}")
    except (SystemExit, ValueError):
        return []
    return list(data.get("ips", {}))


def kill_connections(ips, port):
    """Close the open sockets of cut-off users only. Removing a user over the
    API rejects new connections but leaves established ones running; this ends
    them without restarting xray for everybody. Needs root (ss -K)."""
    for ip in ips:
        r = subprocess.run(["ss", "-K", "dst", ip, "sport", "=", f":{port}"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"xlink: could not close sockets of {ip}: {r.stderr.strip()}", file=sys.stderr)


def sub_sync_once(a):
    today = time.strftime("%Y-%m-%d")
    with db_lock(a.db):
        db = db_load(a.db)
        if a.api:
            apply_usage(db, parse_stats(xray_api(a.api, "statsquery", "-pattern", "user>>>", "-reset")))
            db_save(a.db, db)
        cfg = load(a.config)
        ib = find_in(cfg, a.inbound)
        added, removed = sync_clients(ib, db, today, a.flow)
    if added or removed:
        save(a.config, cfg, a, rolling="sub-sync")
        if a.api:  # apply to the running xray without a restart
            if removed:
                ips = {ip for c in removed for ip in online_ips(a.api, c["email"])}
                xray_api(a.api, "rmu", f"-tag={ib['tag']}", *[c["email"] for c in removed])
                if not a.no_kill: kill_connections(ips, ib["port"])
            if added:
                one = copy.deepcopy(ib); one["settings"]["clients"] = added
                tmp = f"{a.config}.xlink-adu.json"
                with open(tmp, "w") as fh: json.dump({"inbounds": [one]}, fh)
                try: xray_api(a.api, "adu", tmp)
                finally: os.unlink(tmp)
        if removed and a.restart_cmd:  # users removed over the API keep open connections
            subprocess.run(a.restart_cmd, shell=True, check=False)
        for c in added: print(f"enabled  {c['email']}", file=sys.stderr)
        for c in removed:
            u = db_find(db, c["email"])
            print(f"disabled {c['email']} ({user_state(u, today)})", file=sys.stderr)
    return db, today


def cmd_sub_sync(a):
    while True:
        db, today = sub_sync_once(a)
        if not a.loop: return
        # Sleep, but wake at once when the DB changes (a new customer, a renewal).
        mtime = lambda: os.stat(a.db).st_mtime_ns if os.path.exists(a.db) else 0
        seen, until = mtime(), time.time() + next_interval(db, today, a.max_mbps,
                                                             a.min_interval, a.max_interval)
        while time.time() < until and mtime() == seen:
            time.sleep(1)


def cmd_sub_setup(a):
    """Turn on what sub-sync needs: local API, per-user traffic counters."""
    cfg = load(a.config)
    cfg.setdefault("stats", {})
    api = cfg.setdefault("api", {})
    api.setdefault("tag", "api")
    api["listen"] = a.api
    api["services"] = sorted(set(api.get("services", [])) | {"HandlerService", "StatsService"})
    lvl = cfg.setdefault("policy", {}).setdefault("levels", {}).setdefault("0", {})
    lvl["statsUserUplink"] = lvl["statsUserDownlink"] = lvl["statsUserOnline"] = True
    save(a.config, cfg, a)


# The subscription responder. Apps (v2rayNG, Hiddify, ...) fetch
# GET /s/<token> and get base64(link lines); the Subscription-Userinfo header
# makes them show used/total/expiry. Warnings are delivered as an extra,
# non-working entry whose name is the message, so no other channel is needed.

NOTICE_ID = "00000000-0000-0000-0000-000000000000"


def notice_link(text):
    return make_link({"protocol": "vless", "address": "127.0.0.1", "port": 1, "id": NOTICE_ID,
                      "encryption": "none", "type": "tcp", "security": "none", "name": text})


def plan_expiry_epoch(plan):
    y, m, d = map(int, plan_expiry(plan).split("-"))
    return int(time.mktime((y, m, d, 0, 0, 0, 0, 0, -1)))


def days_left(u, today):
    y, m, d = map(int, today.split("-"))
    return (plan_expiry_epoch(u["plans"][-1]) - int(time.mktime((y, m, d, 0, 0, 0, 0, 0, -1)))) // 86400


def sub_notices(u, today, warn_frac=0.1, warn_days=3):
    """Messages the customer should see in the app's server list."""
    state = user_state(u, today)
    if state == "expired": return ["EXPIRED - renew to reconnect"]
    if state == "over-quota": return ["DATA FINISHED - renew to reconnect"]
    if state == "disabled": return ["DISABLED"]
    out = []
    quota = int(u["plans"][-1]["quota_gb"] * GB)
    left = quota - u["used_bytes"]
    if left <= 0:
        out.append(f"Plan data finished - using reserve: {reserve_left(u) / GB:.1f} GB left - renew")
    elif left <= quota * warn_frac:
        out.append(f"Only {left / GB:.1f} GB left - renew soon")
    if days_left(u, today) <= warn_days:
        out.append(f"{days_left(u, today)} day(s) left - renew soon")
    return out


def sub_response(u, today, links):
    """(body, headers) for one customer. LINKS are the working share links."""
    notices = sub_notices(u, today)
    lines = [notice_link(n) for n in notices]
    if user_state(u, today) == "ok": lines += links
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Subscription-Userinfo": (f"upload=0; download={u['used_bytes']}; total={allowance(u)}; "
                                  f"expire={plan_expiry_epoch(u['plans'][-1])}"),
        "Profile-Update-Interval": "1",   # hours
        "Cache-Control": "no-store",
    }
    return b64e("\n".join(lines) + "\n"), headers


def cmd_sub_serve(a):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    ib = find_in(load(a.config), a.inbound)
    pbk = pbk_from(ib, a.pbk)
    flow = a.flow

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            token = self.path[3:] if self.path.startswith("/s/") else ""
            u = None
            if len(token) == 32:
                u = next((x for x in db_load(a.db)["users"] if x["token"] == token), None)
            if not u or not u["plans"]:
                self.send_error(404); return
            c = {"id": u["uuid"]}
            if flow: c["flow"] = flow
            body, headers = sub_response(u, time.strftime("%Y-%m-%d"),
                                         [inbound_link(ib, c, a.host, pbk, a.label or a.host)])
            self.send_response(200)
            for k, v in headers.items(): self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args): pass   # tokens are secrets; keep them out of logs

    host, _, port = a.listen.rpartition(":")
    ThreadingHTTPServer((host, int(port)), H).serve_forever()


def cmd_decode(a):
    print(json.dumps(to_outbound(parse_link(a.link), a.tag), indent=2, ensure_ascii=False))


def cmd_encode(a):
    o = json.load(sys.stdin if a.file == "-" else open(a.file))
    print(make_link(from_outbound(o)))


def main():
    ap = argparse.ArgumentParser(prog="xlink", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)

    def sub(name, fn, *args, write=False):
        p = sp.add_parser(name)
        for x in args: p.add_argument(x)
        if write: p.add_argument("--no-test", action="store_true", help="skip `xray run -test`")
        p.set_defaults(fn=fn)
        return p

    sub("list", cmd_list, "config")
    p = sub("import", cmd_import, "config", "link", write=True)
    p.add_argument("--tag"); p.add_argument("--first", action="store_true",
                                            help="insert as first outbound (the default route)")
    sub("export", cmd_export, "config", "tag")
    sub("rm", cmd_rm, "config", "tag", write=True)
    p = sub("set", cmd_set, "config", "tag", write=True); p.add_argument("pairs", nargs="+")
    sub("users", cmd_users, "config")
    p = sub("user-add", cmd_user_add, "config", "inbound", "name", write=True)
    p.add_argument("--flow"); p.add_argument("--host"); p.add_argument("--pbk")
    sub("user-rm", cmd_user_rm, "config", "inbound", "name", write=True)
    p = sub("user-link", cmd_user_link, "config", "inbound", "name")
    p.add_argument("--host", required=True); p.add_argument("--pbk"); p.add_argument("--label")
    for name in ("sub-user-add", "sub-renew"):
        p = sub(name, cmd_sub_grant, "db", "email")
        p.add_argument("--days", type=int, required=True)
        p.add_argument("--gb", type=float, required=True)
        p.add_argument("--order", help="payment/order id; repeating it is a no-op")
        p.add_argument("--note")
        p.add_argument("--base-url", help="e.g. https://example.com (prints the full subscription URL)")
    p = sub("sub-topup", cmd_sub_topup, "db", "email")
    p.add_argument("--gb", type=float, required=True); p.add_argument("--order")
    sub("sub-disable", cmd_sub_disable, "db", "email")
    sub("sub-list", cmd_sub_list, "db")
    p = sub("sub-serve", cmd_sub_serve, "db", "config", "inbound")
    p.add_argument("--host", required=True, help="address customers connect to (a domain, not an IP)")
    p.add_argument("--listen", default="127.0.0.1:8480", help="put a TLS reverse proxy in front")
    p.add_argument("--flow", default="xtls-rprx-vision"); p.add_argument("--pbk"); p.add_argument("--label")
    p = sub("sub-setup", cmd_sub_setup, "config", write=True)
    p.add_argument("--api", required=True, help="local address for the xray API, e.g. 127.0.0.1:10085")
    p = sub("sub-sync", cmd_sub_sync, "db", "config", "inbound", write=True)
    p.add_argument("--api", help="xray API address; without it only CONFIG is updated")
    p.add_argument("--flow", default="xtls-rprx-vision", help="flow for added users ('' for none)")
    p.add_argument("--no-kill", action="store_true", help="do not close a cut-off user's open sockets")
    p.add_argument("--restart-cmd", help="fallback: run after a user is cut off (interrupts everyone)")
    p.add_argument("--loop", action="store_true", help="keep running, polling adaptively")
    p.add_argument("--max-mbps", type=float, default=100, help="fastest a user can go (sets poll rate)")
    p.add_argument("--min-interval", type=float, default=15)
    p.add_argument("--max-interval", type=float, default=300)
    p = sub("decode", cmd_decode, "link"); p.add_argument("--tag")
    sub("encode", cmd_encode, "file")
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
