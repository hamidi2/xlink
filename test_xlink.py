import base64, json, unittest
import xlink

VLESS = ("vless://11111111-1111-1111-1111-111111111111@203.0.113.7:443?encryption=none"
         "&flow=xtls-rprx-vision&security=reality&sni=example.com&fp=chrome"
         "&pbk=PUBKEY&sid=abcd&type=tcp#relay")
LINKS = [
    VLESS,
    "trojan://p%40ss@example.com:443?security=tls&sni=example.com&type=ws&host=h.example.com&path=%2Fws#t1",
    "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=tls"
    "&sni=example.com&alpn=h2%2Chttp%2F1.1&type=grpc&serviceName=svc#g1",
    "vless://11111111-1111-1111-1111-111111111111@[2001:db8::1]:8443?encryption=none&security=none&type=httpupgrade&path=%2Fup#v6",
    "ss://YWVzLTI1Ni1nY206c2VjcmV0@198.51.100.5:8388#s1",
]


def rt(link):
    return xlink.make_link(xlink.from_outbound(xlink.to_outbound(xlink.parse_link(link))))


class RoundTrip(unittest.TestCase):
    def test_links_survive_round_trip(self):
        for link in LINKS:
            with self.subTest(link=link[:30]):
                self.assertEqual(rt(link), link)

    def test_vmess_round_trip_is_stable(self):
        j = {"v": "2", "ps": "vm", "add": "1.2.3.4", "port": "8443",
             "id": "11111111-1111-1111-1111-111111111111", "aid": "0",
             "net": "ws", "host": "h.example.com", "path": "/p", "tls": "tls", "sni": "a.com"}
        link = "vmess://" + base64.b64encode(json.dumps(j).encode()).decode()
        o1 = xlink.to_outbound(xlink.parse_link(link))
        o2 = xlink.to_outbound(xlink.parse_link(xlink.make_link(xlink.from_outbound(o1))))
        self.assertEqual(o1, o2)
        self.assertEqual(o1["streamSettings"]["wsSettings"], {"path": "/p", "host": "h.example.com"})

    def test_legacy_ss_link(self):
        raw = base64.b64encode(b"aes-256-gcm:secret@198.51.100.5:8388").decode()
        f = xlink.parse_link(f"ss://{raw}#old")
        self.assertEqual((f["method"], f["password"], f["address"], f["port"]),
                         ("aes-256-gcm", "secret", "198.51.100.5", 8388))


class Outbound(unittest.TestCase):
    def test_reality_fields(self):
        o = xlink.to_outbound(xlink.parse_link(VLESS))
        self.assertEqual(o["tag"], "relay")
        user = o["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user["flow"], "xtls-rprx-vision")
        r = o["streamSettings"]["realitySettings"]
        self.assertEqual((r["serverName"], r["publicKey"], r["shortId"]), ("example.com", "PUBKEY", "abcd"))

    def test_xhttp_extra_is_json(self):
        link = ("vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none"
                "&security=tls&sni=example.com&type=xhttp&host=example.com&path=%2Fx&mode=auto"
                "&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#x1")
        o = xlink.to_outbound(xlink.parse_link(link))
        self.assertEqual(o["streamSettings"]["xhttpSettings"]["extra"], {"xPaddingBytes": "100-1000"})
        self.assertEqual(rt(link), link)

    def test_unsupported_protocol_exits(self):
        with self.assertRaises(SystemExit):
            xlink.from_outbound({"tag": "direct", "protocol": "freedom"})


class Inbound(unittest.TestCase):
    IB = {"tag": "in", "port": 443, "protocol": "vless",
          "settings": {"clients": [{"id": "11111111-1111-1111-1111-111111111111",
                                    "flow": "xtls-rprx-vision", "email": "alice"}]},
          "streamSettings": {"network": "tcp", "security": "reality",
                             "realitySettings": {"serverNames": ["example.com"],
                                                 "shortIds": ["", "abcd"], "privateKey": "x"}}}

    def test_user_link_matches_client_link(self):
        c = self.IB["settings"]["clients"][0]
        link = xlink.inbound_link(self.IB, c, "203.0.113.7", "PUBKEY", "relay")
        self.assertEqual(link, VLESS)

    def test_reality_without_pbk_exits(self):
        c = self.IB["settings"]["clients"][0]
        with self.assertRaises(SystemExit):
            xlink.inbound_link(self.IB, c, "203.0.113.7", None, "relay")


class Subscriptions(unittest.TestCase):
    def setUp(self):
        self.db = {"schema": 1, "users": []}
        self.u, _ = xlink.db_grant(self.db, "ali", 30, 50, "2026-01-10", create=True, order="o1")

    def test_new_user(self):
        self.assertEqual(len(self.u["token"]), 32)
        self.assertEqual(xlink.plan_expiry(self.u["plans"][-1]), "2026-02-09")
        self.assertEqual(xlink.user_state(self.u, "2026-01-11"), "ok")

    def test_states(self):
        self.assertEqual(xlink.user_state(self.u, "2026-02-09"), "expired")
        self.u["used_bytes"] = 50 * xlink.GB
        self.assertEqual(xlink.user_state(self.u, "2026-01-11"), "over-quota")
        self.u["used_bytes"] = 0; self.u["active"] = False
        self.assertEqual(xlink.user_state(self.u, "2026-01-11"), "disabled")

    def test_renew_keeps_identity_and_revives(self):
        uuid_, token = self.u["uuid"], self.u["token"]
        self.u["used_bytes"] = 60 * xlink.GB; self.u["active"] = False
        u, changed = xlink.db_grant(self.db, "ali", 30, 20, "2026-03-01", create=False, order="o2")
        self.assertTrue(changed)
        self.assertEqual((u["uuid"], u["token"], u["used_bytes"], u["active"]), (uuid_, token, 0, True))
        self.assertEqual(len(u["plans"]), 2)
        self.assertEqual(xlink.user_state(u, "2026-03-02"), "ok")

    def test_same_order_is_a_noop(self):
        self.u["used_bytes"] = 123
        u, changed = xlink.db_grant(self.db, "ali", 30, 50, "2026-01-12", create=False, order="o1")
        self.assertFalse(changed)
        self.assertEqual((len(u["plans"]), u["used_bytes"]), (1, 123))

    def test_errors(self):
        for kw in ({"email": "ali", "create": True},        # duplicate
                   {"email": "nobody", "create": False},     # renew unknown
                   {"email": "sara", "create": True, "order": "o1"}):  # order reused
            with self.subTest(kw=kw), self.assertRaises(SystemExit):
                xlink.db_grant(self.db, kw["email"], 30, 50, "2026-01-12",
                               create=kw["create"], order=kw.get("order"))

    def test_parse_stats_sums_both_directions(self):
        text = json.dumps({"stat": [
            {"name": "user>>>ali>>>traffic>>>uplink", "value": "10"},
            {"name": "user>>>ali>>>traffic>>>downlink", "value": 5},
            {"name": "user>>>idle>>>traffic>>>downlink"},
            {"name": "inbound>>>api>>>traffic>>>downlink", "value": 99}]})
        self.assertEqual(xlink.parse_stats(text), {"ali": 15, "idle": 0})
        self.assertEqual(xlink.parse_stats(""), {})

    def test_sync_cuts_off_and_revives(self):
        other = {"email": "personal", "id": "x"}
        ib = {"tag": "in", "settings": {"clients": [other]}}
        added, removed = xlink.sync_clients(ib, self.db, "2026-01-11", "f")
        self.assertEqual(added, [{"email": "ali", "id": self.u["uuid"], "flow": "f"}])
        self.assertEqual(xlink.sync_clients(ib, self.db, "2026-01-11", "f"), ([], []))  # stable
        xlink.apply_usage(self.db, {"ali": 50 * xlink.GB, "stranger": 1})
        added, removed = xlink.sync_clients(ib, self.db, "2026-01-11", "f")
        self.assertEqual([c["email"] for c in removed], ["ali"])
        self.assertEqual(ib["settings"]["clients"], [other])  # unmanaged client untouched
        xlink.db_grant(self.db, "ali", 30, 50, "2026-01-11", create=False)
        added, _ = xlink.sync_clients(ib, self.db, "2026-01-11", "")
        self.assertEqual(added, [{"email": "ali", "id": self.u["uuid"]}])

    def test_interval_shrinks_near_the_limit(self):
        args = ("2026-01-11", 100, 15, 300)
        self.assertEqual(xlink.next_interval(self.db, *args), 300)
        self.u["used_bytes"] = 50 * xlink.GB - 1000 * 1000 * 1000   # 1 GB left -> 80 s at 100 Mbit/s
        self.assertEqual(xlink.next_interval(self.db, *args), 40)
        self.u["used_bytes"] = 50 * xlink.GB - 1
        self.assertEqual(xlink.next_interval(self.db, *args), 15)
        self.u["used_bytes"] = 50 * xlink.GB
        self.assertEqual(xlink.next_interval(self.db, *args), 300)   # nobody left to watch

    def test_reserve_is_spent_after_quota_and_survives_renewal(self):
        xlink.db_topup(self.db, "ali", 10, "2026-01-11", order="t1")
        _, changed = xlink.db_topup(self.db, "ali", 10, "2026-01-11", order="t1")
        self.assertFalse(changed)
        self.u["used_bytes"] = 54 * xlink.GB                      # 4 GB into the reserve
        self.assertEqual(xlink.user_state(self.u, "2026-01-11"), "ok")
        self.assertEqual(xlink.reserve_left(self.u), 6 * xlink.GB)
        self.u["used_bytes"] = 60 * xlink.GB
        self.assertEqual(xlink.user_state(self.u, "2026-01-11"), "over-quota")
        self.u["used_bytes"] = 54 * xlink.GB
        xlink.db_grant(self.db, "ali", 30, 50, "2026-01-20", create=False)
        self.assertEqual((self.u["used_bytes"], self.u["reserve_bytes"]), (0, 6 * xlink.GB))

    def test_subscription_body_and_notices(self):
        def lines(today):
            body, h = xlink.sub_response(self.u, today, ["vless://real"])
            return base64.b64decode(body).decode().split(), h
        got, h = lines("2026-01-11")
        self.assertEqual(got, ["vless://real"])
        self.assertIn(f"total={50 * xlink.GB}; expire=", h["Subscription-Userinfo"])
        self.u["used_bytes"] = 46 * xlink.GB                      # under 10% left
        got, h = lines("2026-01-11")
        self.assertEqual(len(got), 2); self.assertIn("فقط 4.0 گیگ", unquote(got[0]))
        self.assertIn(f"download={46 * xlink.GB};", h["Subscription-Userinfo"])
        self.assertIn("2 روز تا پایان", xlink.sub_notices(self.u, "2026-02-07")[-1])
        got, _ = lines("2026-02-09")                              # expired: notice only
        self.assertEqual(len(got), 1); self.assertIn("منقضی", unquote(got[0]))

    def test_file_round_trip_is_private(self):
        import os, stat, tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "users.json")
            xlink.db_save(path, self.db)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(xlink.db_load(path), self.db)


if __name__ == "__main__":
    unittest.main()
