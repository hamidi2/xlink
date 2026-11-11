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


def save(path, cfg, args):
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
    while os.path.exists(bak):
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
    p = sub("decode", cmd_decode, "link"); p.add_argument("--tag")
    sub("encode", cmd_encode, "file")
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
