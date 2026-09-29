# Tilder

Work on all your machines from the browser as if they were one: terminals,
files and copies between machines, with no ports to open, no password
accounts, and a server that cannot read what you do. Hosted at
[tilder.run](https://tilder.run).

This repository is the part of Tilder you trust with your machines, published
so that trust can be checked rather than taken:

| Where | What |
| --- | --- |
| `go/cmd/tilder`, `go/internal/agent`, `go/internal/holder` | The agent that runs on your machine: terminals, files, copies between your machines |
| `go/internal/identity` | Keys and every signed statement: device certificates, grants, removed devices, offers |
| `go/internal/update` | Self-update: only a release signed by the release key, only a newer one |
| `proto/` | The wire between browser, agent and server |
| `web/src/platform`, `web/src/model` | The console's key handling: device keys that cannot be exported, the root wrapped under a passkey or recovery code, the sealed workspace directory, adding a device over a PAKE |
| `vectors/` | Every signed byte format, shared by the Go and TypeScript code |

What this code guarantees, and you can check here:

- **Keys never leave your devices.** A browser's device key is created
  non-extractable; the root key exists only wrapped, opened in memory for one
  admin action and dropped.
- **Your machines trust your root, not the server.** An agent checks every
  offer, grant and removal against the root key it was joined with. The
  rendezvous server only introduces peers; a server that lies cannot open a
  shell or read a file.
- **Traffic is peer to peer and encrypted.** WebRTC with DTLS pinned to the
  fingerprint in a signed offer; through a relay when needed, which sees only
  ciphertext. On one LAN, copies go over TLS pinned the same way.

The rendezvous server and the console's interface are not published: the
design treats the server as untrusted, so nothing above depends on it.

## License

Apache-2.0 ([`LICENSE`](LICENSE)).

## Security

Report a vulnerability privately: see [`SECURITY.md`](SECURITY.md).
