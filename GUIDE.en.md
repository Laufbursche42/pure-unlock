# Guide

> **Important for error reports:** switch on the **Diagnostic log** at the bottom of the page *before* you connect to the scooter. Only then is the full connection handshake captured - and those are exactly the lines we need in a [ticket](https://github.com/Laufbursche42/Laufbursche42/issues) to reproduce a problem.

## What you need
- A PURE e-scooter (ZYD / HobbyWing ESC).
- A phone or computer with **Chrome**, **Edge**, or on iOS **Bluefy**. Safari and Firefox cannot do Web Bluetooth.

## Connecting
1. Turn on Bluetooth and wake the scooter.
2. Tap **Connect** and pick the scooter from the list.
3. If it is not listed, tick **Show all devices** and try again. The real check is the Bluetooth service found (0xF1F0), not the advertised name.
4. If your device requires a password (the live field shows TYPE B), enter the PIN in the **PIN** field and tap **Send PIN**. The PIN travels in plaintext over Bluetooth; there is no encryption.
5. Once connected, the live-values, lock, speed and settings cards appear.

## Reading live values
The AT channel reports password status, device type, drive mode, NFC, turn-signal voice and LUDO. Each tile appears once its value has arrived. The ride telemetry (speed, battery, current, temperature, mileage) streams continuously on the binary channel. The page shows that data as raw frames under **All received binary frames**.

## Setting the speed
- **Unlock** writes the value from the **Open** field, **Lock** writes the **eKFV / legal** field into the limit register (address 32, value times ten, RW-parameter 0x17).
- **Set exact** writes any km/h value directly. The register allows up to 60.
- Important: an echo in the log only means the scooter accepted the frame. The limit cannot be read back, so only behaviour on the device shows the value is active.

## Lock
In the **Lock** card you lock or unlock the scooter (immobilizer). Note: the lock sits in the same 0xAB frame as light, gear, cruise and unit. Because the current state cannot be read back, locking writes the complete settings frame from the last chosen values. A locked scooter can only be unlocked again over Bluetooth.

## More settings
- **AT toggles** (NFC, turn-signal voice, drive mode, LUDO) are written individually.
- **0xAB fields** (headlight, atmosphere light, cruise, zero-start, unit, gear) share ONE frame. Each Set writes all of these fields together from the last chosen values. Check the other fields before you send.
- **Wheel size** and **modulation depth** go as RW-parameters and are risky. Wheel size only changes the speedometer calculation, not the real speed.

## Advanced settings (engine level)
**Send a raw frame** sends your hex bytes unchanged on the chosen channel (DATA binary or CMD/AT). **Build an ESC frame** takes an opcode and payload and adds head 0x01 and CRC16/MODBUS for you. **AT command** sends an ASCII line like AT+NFC? on the CMD channel.

## Shortcuts
Copy the link to your home screen, then one tap unlocks or locks directly. On iOS via Bluefy, and the scooter must have been connected normally once before.

## If something does not work
- Cannot connect? Check that the browser supports Web Bluetooth, Bluetooth is on and the scooter is awake. Retry with **Show all devices**.
- Nothing happens after a command? Check the log: if it says "sent" but no "confirmed", the firmware did not acknowledge the frame.
- Password rejected (OK+PWD:N)? Check the PIN. If it says TYPE A, the device needs no password at all.
- **Diagnostics: list all devices** in the log area shows every Bluetooth service of a device without writing anything - useful for support.

## Contribute
Want to find out if and how tuning works on your scooter? Test this tool on your own vehicle and open a ticket on [GitHub](https://github.com/Laufbursche42/Laufbursche42/issues) - with your model and what worked (or did not). That way we figure out together what is possible on which model.
