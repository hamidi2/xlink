# xlink

A single-file, dependency-free tool to manage [Xray-core](https://github.com/XTLS/Xray-core)
configs from the command line and to convert between Xray JSON and the share
links used by v2rayNG, Hiddify, v2rayN and similar clients.

- List, add, edit and remove **outbounds** in a client config.
- List, add and remove **users** of a server inbound and print their share links.
- Convert a share link to outbound JSON and back, without touching any file.
- Every write is checked with `xray run -test` and the previous file is kept
  as `CONFIG.bak-<timestamp>`. A config Xray rejects is never installed.

Supported protocols: VLESS, VMess, Trojan, Shadowsocks.
Transports: tcp/raw, ws, grpc, httpupgrade, xhttp. Security: none, tls, reality.

## Install

Python 3.8+ and nothing else:

    curl -o xlink https://raw.githubusercontent.com/hamidi2/xlink/main/xlink.py
    chmod +x xlink

## Client side

    xlink list   /usr/local/etc/xray/config.json
    xlink import /usr/local/etc/xray/config.json 'vless://...#my-server'
    xlink export /usr/local/etc/xray/config.json my-server
    xlink set    /usr/local/etc/xray/config.json my-server address=203.0.113.7 port=443
    xlink rm     /usr/local/etc/xray/config.json my-server

`import` on an existing tag replaces it and keeps local-only settings (`mux`,
`sockopt`). `set` takes share-link field names (`address`, `port`, `sni`, `fp`,
`pbk`, `sid`, `path`, `host`, `flow`, ...); an empty value removes the field.

## Server side

    xlink users     config.json
    xlink user-add  config.json INBOUND alice --flow xtls-rprx-vision --host 203.0.113.7
    xlink user-link config.json INBOUND alice --host 203.0.113.7
    xlink user-rm   config.json INBOUND alice

`INBOUND` is an inbound tag or port. For REALITY inbounds the public key is
derived from the private key with `xray x25519`; pass `--pbk` if `xray` is not
installed on that machine.

## Subscriptions (quota and expiry per customer)

A small JSON database is the source of truth for customers; the inbound's
client list is derived from it. Each customer keeps one permanent UUID and one
permanent subscription URL, so renewing never requires a new link.

    xlink sub-setup    config.json --api 127.0.0.1:10085       # once: API + per-user counters
    xlink sub-user-add users.json alice --days 30 --gb 50 --base-url https://example.com
    xlink sub-renew    users.json alice --days 30 --gb 50      # new plan, same URL
    xlink sub-topup    users.json alice --gb 10                # reserve, used after the quota
    xlink sub-disable  users.json alice
    xlink sub-list     users.json

    # long-running pieces (run them as services)
    xlink sub-sync  users.json config.json INBOUND --api 127.0.0.1:10085 --loop
    xlink sub-serve users.json config.json INBOUND --host example.com   # behind a TLS proxy

- `sub-sync` reads per-user traffic from the Xray API, removes users that ran
  out of data or time and re-adds renewed ones. Changes go to the running Xray
  over its API (no restart) and to the config file. It polls: more often when a
  user is close to the limit, and at once when the database changes. A user can
  overshoot by what they transfer in one polling interval (15 s minimum).
- When a user is cut off, their open sockets are closed with `ss -K` (needs
  root), matched by client IP: other users behind the same IP reconnect.
- `sub-serve` answers `GET /s/<token>` with the user's link(s) and a
  `Subscription-Userinfo` header, which v2rayNG/Hiddify show as used/total/expiry.
  Low-data, expiry and "finished" warnings appear as an extra entry in the
  server list, so no other notification channel is needed.
- `--order ID` on add/renew/topup makes the command idempotent, so a payment
  webhook can safely retry it.

## Conversion only

    xlink decode 'trojan://secret@example.com:443?security=tls&type=ws&path=%2Fws#t1'
    xlink encode outbound.json        # or "-" for stdin

Use `-` as the config path to read from stdin and write to stdout. Restart Xray
yourself after a change; xlink never restarts services (`sub-sync` applies
user changes live through the Xray API instead).

## Tests

    python3 -m unittest -v

## Limits

Only the first server and first user of an outbound are represented in a link.
Fields that share links cannot express (routing, balancers, `sockopt`, `mux`)
are preserved in the config but are not part of exported links.

## License

MIT
