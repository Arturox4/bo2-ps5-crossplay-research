# BO2 PS5 ↔ PC LAN Crossplay — Research Notes

Reverse-engineering notes and Python tools from an attempt to make the **PS5 port of Call of Duty: Black Ops II** (released digitally July 2026) talk to the **PC version** over LAN, so PC and PS5 players could share a Zombies lobby.

> **Status: stopped.** The PS5 discovers a PC-hosted game, completes the full Demonware DTLS handshake with it, and its encrypted lobby traffic can be decrypted (`joinParty`). It never accepts any reply we send back. Getting past that point needs the PS5 side of the code, and the test console (firmware 14.22) has no jailbreak.

## What works

| Step | Result |
|---|---|
| PC sees a PS5 LAN game (`getinfo` / `infoResponse`) | ✅ Works |
| PS5 sees a game advertised by the PC | ✅ Works |
| NAT-traversal hello (`0x0d` → `0x0c` echo), both directions | ✅ Works (needs the Tiger-192 address tag) |
| DTLS-style association `Init → InitAck → CookieEcho → CookieAck` | ✅ Works, PC as client **and** as host |
| Session key derivation (ECDH P-224 + Tiger-192) | ✅ Works |
| Decrypting PS5 data packets (3DES-CBC) | ✅ Works — first message is `joinParty` |
| Lobby reply (`partyaccept`) accepted by the PS5 | ❌ Ignored in every form tried |
| In-game state compatibility PC ↔ PS5 | ❓ Unknown |

Full details, packet layouts and every experiment are in **[docs/FINDINGS.md](docs/FINDINGS.md)**.

## Protocol summary

**Discovery** — UDP 17476, subnet broadcast.

```
request : 57 04 40 | ff ff ff ff | 32 | "getinfo xxx"
response: 57 04 04 | ff ff ff ff | "infoResponse\n" + \key\value pairs
          (protocol 2097, hw 13, seckey, secid, hostaddr, ...)
```

The 3-byte prefix (`57 04 40` / `57 04 04`) is required; without it the PS5 answers nothing.

**Connection** — UDP 3074 ↔ 3074, Demonware `bdNATTravClient` + `bdDTLS*`.

```
0x0d hello   0d 02 00 | 10 random bytes | tiger192(dst_ip + port_le)[:4] | src(6) | dst(6)
0x01 Init    01 02 0000 0000 | initTag(2) | secid(8)
0x02 InitAck cookie: time_ms(4 LE) | sig(4) | tags | addr(6) | secid(8)
0x03 Echo    hdr | full InitAck | commonaddr(37) | secid(8) | ECC-224 pubkey (libtomcrypt DER, padded to 100)
0x04 Ack     hdr | host ECC-224 pubkey (100) | secid(8)
session key = Tiger192(ECDH shared x (28 bytes) || host seckey (16))
0x06 Data    06 02 | vtag(2) | counter(2 LE) | IV(8) | len(2 LE) | 3DES-CBC(payload)
```

Decrypted PS5 payload: `8-byte nonce | "joinParty\0" | 31 08 00 00 (=2097) | account id(8) | flags…`

## Where it is blocked

- The PC host answers `joinParty` with an out-of-band text message (`ff ff ff ff` + `"<digit>partyaccept %x %i"`, sent twice).
- The PS5's `joinParty` arrives **without** `ff ff ff ff` or the leading digit — a bare Demonware message. The PS5 port wraps party messages differently from the PC build.
- About 20 reply variants were tried (encrypted bare `partyaccept` mirroring `joinParty`, raw OOB, different headers). The PS5 never sent anything but `joinParty`; it kept retrying and re-associating every 5–16 s.
- The reply format the PS5 expects can't be derived from the PC binary. It needs live trial and error with a new idea, or access to the PS5 code.

Even if networking worked, PS5 Zombies lobbies cap at 4 players.

## Tools (`tools/`)

Python 3 + [`cryptography`](https://pypi.org/project/cryptography/). Captures use `tshark` (Wireshark + Npcap), because on the test machine the Windows firewall blocked inbound UDP to Python. Code comments are in Spanish.

| Script | Purpose |
|---|---|
| `bo2_lan_probe.py` | Initial LAN port probe |
| `udp_listen_all.py` | Listen on (almost) every UDP port at once |
| `ps5_getinfo.py` | Send the exact PS5 `getinfo` discovery request |
| `fake_host.py` | Advertise a fake PC game to the PS5 |
| `ps5_responder.py` | Try reply variants to the `0x0d` hello |
| `ps5_variants.py` | Advertise games one at a time to work out the 14-byte hello block |
| `ps5_client.py` | PC joins a PS5-hosted game (hello + Init) |
| `ps5_cookie.py` | Init + CookieEcho variants against a PS5 host |
| `bd_tiger.py` | Demonware Tiger-192 and the `0x0d` address tag |
| `ps5_assoc_lib.py` | Shared helpers (libtomcrypt-style ECC-224 keys, headers) |
| `ps5_assoc.py` | Full DTLS association as client + session key |
| `ps5_host.py` | PC acts as DTLS host, decrypts PS5 data, sends `partyaccept` variants |
| `ps5_join.py` | PC as client of a PS5 host, sends encrypted `joinParty` |

### Setup notes

- `pip install -r requirements.txt`
- `bd_tiger.py` reads the Tiger S-boxes from your own `t6zm.exe` (path at the top of the file). No game files are included here.
- `fake_host.py`, `ps5_host.py`, `ps5_responder.py` and `ps5_variants.py` use `host_payloads.txt` as an `infoResponse` template: one line, the hex of a real response captured from your PS5. `tools/host_payloads.example.txt` is a sanitized sample (hostname, keys and public IP replaced). Copy it to `host_payloads.txt` or use your own capture.
- `ps5_join.py` uses a placeholder account ID; replace it with the one from your own decrypted `joinParty`.
- Run the scripts from inside `tools/` so they can import each other.
- The PS5 only sends LAN traffic at specific moments (opening the server browser, joining), so every test has to be timed with what you do on the console.

## Playing 8-player Zombies today

Everyone on PC with [Plutonium](https://plutonium.pw) (T6) in LAN mode; PS5 controllers work on PC over USB/Bluetooth. Raise `sv_maxclients` / `party_maxplayers` to 8 in a custom game, or use the T6 QoL modpack (host only).

## References

- Plutonium forum — *BO2 PS5 LAN discovery protocol research* (topic 45705)
- Plutonium forum — *How to have more people in zombies* (topic 41646)
- Plutonium forum — *T6 ZM QoL Modpack* (topic 46019)

## Disclaimer

Independent interoperability research on hardware and software the author owns, done on a private LAN. No game files, decompiled code or game keys are distributed, the PS5 was not modified, and nothing here touches online services. Not affiliated with Activision, Treyarch, Demonware, Sony or Plutonium.
