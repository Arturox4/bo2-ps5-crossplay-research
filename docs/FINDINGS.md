# Findings: BO2 LAN crossplay between PC and PS5

Tests ran on 16–17 November 2026.
Original goal: play Zombies (Origins, survival) with 8 players across PC and PS5 over LAN.

## 1. Conclusion

Crossplay was not achieved. PC and PS5 find each other on the LAN, complete the full Demonware DTLS handshake in both directions, and the PS5's encrypted lobby data can be decrypted. The PS5 never accepts the lobby reply (`partyaccept`) in any form we tried, and the format it expects can't be derived from the PC binary.

Two limits remain even if networking worked:

- PS5 Zombies lobbies cap at 4 players.
- Nobody knows whether the PC and PS5 game engines use the same in-game state format (protocol 2097 vs. whatever Plutonium uses).

What works today: 8 players in Origins with everyone on PC using Plutonium in LAN mode.

## 2. Context

- BO1 and BO2 came out digitally for PS4 and PS5 on 9 July 2026. They are direct ports: no remaster, no DLC.
- Official crossplay is PS4 ↔ PS5 only. PC and Xbox are separate.
- Plutonium (T6) is PC-only and allows up to 8 players in Zombies.
- No public project connects the PS5 port with PC.
- The test PS5 runs firmware 14.22: no jailbreak is available.

## 3. Setup

- PC on Wi-Fi, Windows 10, no admin rights. PS5 on the same subnet.
- Plutonium r4542 and BO2 (Steam) installed.
- Wireshark 4.6.9 + Npcap 1.90 for captures (the Windows firewall blocked inbound UDP to Python; Npcap captures below the firewall).

## 4. PS5 LAN protocol

### 4.1 Game discovery

- UDP port 17476 (source and destination), subnet broadcast.
- The PS5 server browser only asks when you open or refresh the list.

Request (19 bytes):

```
57 04 40 | ff ff ff ff | 32 | "getinfo xxx"
```

Response (also broadcast):

```
57 04 04 | ff ff ff ff | "infoResponse\n" + \key\value pairs
```

Keys: `challenge, netfieldchk, protocol (2097), sessionmode, hostname, mapname, isInGame, clients, com_maxclients, gametype, ff, hw (13), seckey, secid, hostaddr`.

The 3-byte prefix (`57 04 40` / `57 04 04`) was missing from the earlier Plutonium forum post. Without it the PS5 answers nothing, either by broadcast or when probing all 65,535 UDP ports.

### 4.2 `hostaddr` (37 bytes, base64)

```
local IP (4) + port (2)
4 empty entries of 6 bytes (00 ff 00 ff 00 00)
public IP (4) + port (2)
1 type byte
```

The port is 3074, stored little-endian (`02 0c`).

### 4.3 The PC as seen from the PS5

- The PS5 lists a game advertised by the PC. Broadcasting an `infoResponse` is enough; answering its `getinfo` is not required.
- The PS5 connects to the **public** address in `hostaddr`, not the local one. If that isn't the PC's IP, the console sends nothing.
- The PS5 shows only one fake game per source IP.

### 4.4 Join attempt

- When joining, the PS5 sends a 29-byte UDP hello from port 3074 to 3074, about once per second.
- If nobody answers, the PS5 shows "unable to join game session".

### 4.5 The `0x0d` hello (29 bytes)

```
[0]      type     = 0d
[1-2]    version  = 02 00
[3-16]   14-byte block
[17-22]  sender address : IP(4) + port(2 LE)
[23-28]  target address : IP(4) + port(2 LE)
```

The 14-byte block = 10 bytes that change on every attempt + 4 fixed bytes. The 4 fixed bytes are the first 4 bytes of **Tiger-192(target IP + port LE)**, unkeyed (verified on 5 samples, ports 3074–3078). `seckey`, `secid` and `hostname` have no effect. The 10 variable bytes are not checked by the receiver. Implemented in `bd_tiger.py`.

### 4.6 Answering the hello

Six reply variants were tried (different type byte, with or without swapped addresses):

- `0e` variants: the PS5 ignores them and keeps sending `0x0d`.
- `0c`, `0f`, `0d` variants: the PS5 stops sending `0x0d` and moves on to `0x01`.

When the PS5 is the host, it answers a correct `0x0d` with the same packet with the type changed to `0c` (an echo). It only answers if the target is its **public** `hostaddr` address.

### 4.7 Identifying the library

`t6zm.exe` (PC) ships the same Demonware library: `bdNATTravClient`, `bdSocketRouter`, `bdDTLSInit/InitAck/CookieEcho/CookieAck/Data/Error`, `bdHMacSHA1`, `bdHashTiger192`, `bdCypherAES`, `bdCypher3Des`, ECC. Working mapping:

- `0x0d` = NAT traversal hello (`bdNATTravClient`)
- `0x01..0x04` = SCTP-style DTLS association with a cookie
- `0x06` = encrypted data

### 4.8 Init / InitAck

```
PC  -> 0x01 Init    : 01 02 0000 0000 | tagPC(2, random) | secid_host(8)
PS5 -> 0x02 InitAck : 02 02 tagPC 0000 | time_ms(4 LE, +~1000/s) | sig?(4) |
                      tagPS5(2) | tagPS5(2) | tagPC(2) | 00000000 | addr_PC(6) | secid(8)   (38 bytes)
```

The `XX XX` field in `0x01` is a random init tag, fixed within one attempt. If the PS5 already said hello to the same address, its next attempt jumps straight to `0x01`.

### 4.9 Real format from the binary — full association

The format was read from `t6zm.exe` with Ghidra 11.4.3 (headless), locating classes through RTTI.

- Common header (6 bytes): `type(1) 02 vtag(2) counter(2)`.
- **CookieEcho** (189 bytes) = `hdr(03, tagPS5)` | the full InitAck as received (38) | client `commonaddr` (37, same layout as `hostaddr`) | host `secid` (8) | ECC-224 public key in libtomcrypt DER (`SEQUENCE{BIT STRING 0, INT 28, INT x, INT y}`), zero-padded to 100 bytes.
- The host checks: cookie signature and age (< 60 s), that it knows the `secid`, and that the ECC key imports.
- **CookieAck** (114) = `hdr(04, tagPC)` | host ECC-224 key (100) | `secid` (8).
- **Session key** (24 bytes) = `Tiger192(ECDH shared secret x (28 bytes) || host seckey (16))`. `seckey` and `secid` come from the `infoResponse`.
- `ps5_assoc.py` runs the whole handshake; the PS5 answered CookieAck on the first try (association state 3, established).
- The PS5's ECC key is the same across sessions.

### 4.10 The PS5 joins the PC as host; its data is decrypted

`ps5_host.py` advertises `PC-HOST` and answers `0d` / Init / CookieEcho as host. The PS5 completed the DTLS handshake and sent data packets.

Data packet `0x06` (80 bytes):

```
06 02 | vtag(2) | counter(2 LE, 1,2,3…) | IV(8) | len(2 LE) = 64 | 64 bytes 3DES-CBC
```

Key = 24-byte session key, IV = the 8 bytes in the packet. The Plutonium build of `t6zm.exe` does **not** encrypt this way (its data layer is modified, without 3DES); the PS5 uses real 3DES. The Steam build was later analyzed too and matches the PS5.

Plaintext (64 bytes):

```
8 bytes that change every packet | "joinParty\0" | 31 08 00 00 (= 2097) |
8-byte account id | flags/data (ff … 01 01 … 01 7f 00 f2 dd f1 01 55 5f)
```

The PS5 repeats it about once per second waiting for an answer. Lobby message names found in the binary: `joinParty, partyaccept, partymember, memberJoin, partyJoinFailed, connectResponse, xupdatepartystate…`

### 4.11 Replying to `joinParty`: ignored

- Host party message table in `t6zm.exe` (`{name, handler, flag}`): `pha, psack, joinParty, memberJoin, localJoin, member, echoreq, finishedloadingdemo, dis, leaderdis, ihear, canthear, profile, profilesack, pgs, pkick, leaguestats, leagueoutcomesack, emblemupdate`.
- The PC host answers `joinParty` with out-of-band text (`ff ff ff ff` + text): `"%ipartyaccept %x %i"` / `"%ipartyJoinFailed %s"` / `"…banned"`. The first character is a digit, the party index. The client accepts it only while in state 5 ("joining") and only from the host's address, then moves to state 0xd. The host sends the message twice (unreliable channel).
- PC game layer: `[channel<<4 | socket byte] + data + Internet-style u16 checksum`. The PS5 plaintext doesn't match this (no `ff ff ff ff`, no recognizable checksum).
- Eight `partyaccept` forms (3DES-encrypted) plus control probes (garbage, wrong vtag) were sent. The PS5 sends bursts of `joinParty` (~10/s, 10–50 packets) and redoes the association every 5–16 s whether we answer or not.
- Reverse test (`ps5_join.py`): PC as **client** of a PS5 host, association OK, 75 encrypted `joinParty` packets (exact copy, other account id, zeroed first block). The PS5 host answered nothing.

### 4.12 Steam binary analyzed: the IV is not the blocker

- The Steam `t6zm.exe` was unpacked locally for analysis and loaded into Ghidra. Its Demonware classes are in clear.
- `0x06` format confirmed (`Data_ser`): `type 06 | ver 02 | vtag(2) | counter(2 LE) | IV(8) | len(2 LE) | 3DES-CBC`.
- The receiver (`Data_deser`) only **reads** the IV and uses it to decrypt; it doesn't verify or derive it. A random IV is fine.
- 3DES/AES is standard libtomcrypt CBC, no extra layer.
- Offline analysis of 492 real packets: IV, first ciphertext block and the 8-byte plaintext header are identical per (key, counter) in 86/86 repeated groups, so the whole packet is deterministic per (key, counter). About 20 candidate formulas were tested (3DES-ECB of the counter in several encodings, Tiger-192 in several orders, HMAC-SHA1, E_k(IV), chained). None matched. They most likely come from a per-session PRNG.
- The 8-byte header is almost certainly a nonce the receiver discards.
- **Key difference:** the PC sends `partyaccept` as a connectionless OOB message (`ff ff ff ff` + digit + text). The PS5's `joinParty` is a bare Demonware message (`[8 bytes][joinParty\0][binary args]`). PC and PS5 wrap party messages differently, and only the PS5 code defines its format.

### 4.13 Final live test: negative

Six tuned variants × 3 rounds with the PS5 joined to `PC-HOST`:

- `nonce(8) + "partyaccept\0" + binary args mirroring joinParty`, encrypted;
- the same with protocol `31 08 00 00` and the host `secid`;
- raw unencrypted OOB (`ff ff ff ff` + `"2partyaccept …"`, and with the `57 04 04` prefix) to port 3074.

The PS5 never sent anything but `joinParty` and kept retrying and re-associating as before. Without a PS5 jailbreak (firmware 14.22) or a published description of the PS5 port's protocol, there is no reasonable way forward.

## 5. Plutonium observations

- In LAN mode it opens UDP 4976 and 3074.
- Its log shows the same Demonware network layer (port 3074).
- It binds that layer to the Ethernet interface (link-local address), not Wi-Fi.
- It doesn't answer the PS5's `getinfo` or hello, either in the menu or hosting a custom game (72 real PS5 hellos, no reply).
- Public Plutonium servers don't answer an out-of-band `getinfo` either, so the PC protocol version couldn't be compared with the PS5's (2097).

## 6. Status table

| Step | Status |
|---|---|
| PC sees the PS5 LAN game | Works |
| PS5 sees a game advertised by the PC | Works |
| PS5 starts connecting to the PC | Works |
| First hello step (`0x0d`) answered | Works (several replies are accepted) |
| PS5 moves to `0x01` with the PC's `secid` | Works |
| PS5 host accepts the PC's `0x0d` | Works (with the Tiger hash) |
| PS5 host answers Init with InitAck | Works |
| CookieEcho / CookieAck (DTLS association) | Works (`ps5_assoc.py`) |
| PS5 joins the PC host (full DTLS) | Works (`ps5_host.py`) |
| PS5 encrypted data (3DES) | Decrypted: `joinParty` |
| Lobby reply (`partyaccept`) | Ignored by the PS5 |
| In-game compatibility PC vs PS5 | Unknown |

## 7. Problems along the way

- With Wi-Fi set as a "Public" network, the Windows firewall dropped inbound UDP to Python. Fixed by capturing with Npcap, which reads below the firewall. (The network was later switched to Private.)
- A silent Wireshark install doesn't include Npcap; it had to be installed separately.
- A wrong capture filter dropped the relevant traffic in one test.
- The PS5 only sends LAN traffic at specific moments, so every test has to be coordinated with what you do on the console.

## 8. Playing 8-player Zombies today (all on PC)

- Each player needs a PC with BO2 and Plutonium. The game is light, so modest laptops work.
- PS5 controllers work on PC over USB or Bluetooth.
- LAN mode without an account, from the Plutonium folder:

  ```
  bin\plutonium-bootstrapper-win32.exe t6zm "<BO2 path>" -lan +name YourName
  ```

- For 8 players: in a custom game raise `sv_maxclients` and `party_maxplayers` to 8 from the console, or use the T6-QoL modpack (only the host installs it). Not tested in these sessions.
