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

    curl -o xlink https://raw.githubusercontent.com/USER/xlink/main/xlink.py
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

## Conversion only

    xlink decode 'trojan://secret@example.com:443?security=tls&type=ws&path=%2Fws#t1'
    xlink encode outbound.json        # or "-" for stdin

Use `-` as the config path to read from stdin and write to stdout. Restart Xray
yourself after a change; xlink never restarts services.

## Tests

    python3 -m unittest -v

## Limits

Only the first server and first user of an outbound are represented in a link.
Fields that share links cannot express (routing, balancers, `sockopt`, `mux`)
are preserved in the config but are not part of exported links.

## License

MIT
