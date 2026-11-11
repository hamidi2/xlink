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


if __name__ == "__main__":
    unittest.main()
