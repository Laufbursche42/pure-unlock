# Laufbursche PURE unlock

A static web page that talks to PURE e-scooters over Web Bluetooth. Connect, read the AT-channel status, and - straight from the browser - set the maximum speed, lock and unlock the scooter, switch drive mode, NFC, turn-signal voice and the live-settings byte (light, cruise, gear, unit). Nothing to install: no app store, no signing, no developer account. It runs in **Bluefy** on iOS and in **Chrome** or **Edge** on Android or desktop.

> **This is a feasibility study - the writes are built byte-correct, but their effect on hardware is unconfirmed, and the live ride telemetry is deliberately NOT decoded.** It exists to show what PURE's Bluetooth protocol makes possible, not to be a finished product; the protocol was reconstructed from the official app (`com.zydtech.Pure`, a HobbyWing-ESC OEM app) and is documented byte for byte. One generic profile covers every PURE model. **What is proven and safe:** the AT command channel (service `0xF2F0`) reads and writes reliably in ASCII - password type, drive mode, NFC, turn-signal voice and LUDO. **What is built but device-untested:** the speed-limit write (RW-parameter `0x17` to register `32`, value x10 on the binary service `0xF1F0`), the lock and the live-settings byte (`0xAB`), and the wheel-size / modulation-depth tuning registers. Every frame is assembled with the real CRC16/MODBUS checksum, but whether the firmware honours a write - or accepts a limit above the legal speed - sits in the controller and must be tested on the device. **What is honestly withheld:** the raw byte offsets and scaling inside the binary telemetry notifications did not decompile from the app, so live speed/battery/current/temperature/mileage are shown only as **raw frames**, never as invented numbers. There is no warranty of any kind. Whatever you do with it, you do at your own risk - read the [Legal](#legal) section before you connect a scooter.

**Open the web app: [laufbursche42.github.io/pure-unlock](https://laufbursche42.github.io/pure-unlock/)**

Or run it yourself, no build step and no dependencies: clone the repo and serve the folder over a local HTTP server. Opening `index.html` directly as a `file://` URL will not work, the page fetches its own documents and browsers block that over `file://`.

```
git clone https://github.com/Laufbursche42/pure-unlock.git
cd pure-unlock
python -m http.server 8000
```

Any static server works. With Node installed, this does the same job:

```
npx serve .
```

Then open the printed address in a browser that supports Web Bluetooth.

**Guide: [Deutsch](GUIDE.de.md) | [English](GUIDE.en.md)** covers everything step by step, from connecting to the first send.

## What it does

- **Live values** - password type, device type, drive mode, NFC, turn-signal voice and LUDO, read from the AT channel. Plus a raw decode of every binary frame the scooter sends, grouped by head/opcode.
- **Speed** - an unlock/lock toggle (open value vs eKFV value) plus an exact km/h set. Writes the `0x17` RW-parameter to register `32` (value x10, register max 60). Write-only: the limit cannot be read back.
- **Lock** - the immobilizer, via the `0xAB` monitor byte (bit 7). That byte also carries light, gear, cruise and unit, so it is always written as a whole.
- **More settings** - NFC, turn-signal voice, drive mode, LUDO (AT, individual and safe); headlight, atmosphere light, cruise, zero-start, unit, gear (one shared `0xAB` frame); wheel size and modulation depth (RW-parameters, risky).
- **Expert** - send a raw frame on either channel, build an ESC frame from an opcode plus payload (head and CRC added for you), or send a raw AT line.
- **Shortcut** - a home-screen link that unlocks or locks in a single tap.

## Protocol (proven)

- Two GATT services: binary **DATA** `0xF1F0` (write `0xF1F1`, notify `0xF1F2`) and ASCII **AT** `0xF2F0` (write `0xF2F1`, notify `0xF2F2`). Scan matches the `0xF1F0` service UUID, not a name.
- Binary frame heads: `0x01` ESC command, `0xAB` monitor/live-settings, `0xA5` transparent. Checksum everywhere on the binary channel is **CRC16/MODBUS** (poly `0x8005` / reflected `0xA001`, init `0xFFFF`, refin+refout, no xorout), appended little-endian low byte first.
- ESC command `[01 op addrBE countBE crcLE]`; RW-parameter `0x17` `[01 17 addrBE wcBE addrBE wcBE byteLen value.. crcLE]`; monitor `[AB 00 0A bitfield limitCruise lm1 lm2 lm3 crcLE]`.
- Register map: addr `32` speed limit (x10, max 60), addr `2` max modulation depth (max 50), addr `23` wheel diameter (x25.4).
- Auth: optional **plaintext** PIN over AT (`AT+PWD[..]` -> `OK+PWD:Y/N`; `AT+TYPE?` -> `OK+TYPE:A` none / `OK+TYPE:B` required). No cryptographic pairing.

## Honesty

Device-untested by design - you test on your own scooter, which is exactly the point of a public tool. The binary telemetry parser did not decompile from the app, so this page refuses to fake decoded ride values and shows the raw frames instead. The `0xAB` live-settings byte cannot be read back, so writing any one of its fields rewrites the whole byte from the last chosen values - the page says so at every such write. An echo means the frame was **accepted**; only behaviour on the device proves it took effect.

## Legal

License: PolyForm Noncommercial, see [License](LICENSE.md). Privacy: nothing leaves your device, see [Privacy](PRIVACY.md). Trademarks: PURE is a trademark of its respective owner, this project is independent, see [Trademarks](TRADEMARKS.md).

Source: https://github.com/Laufbursche42/pure-unlock
