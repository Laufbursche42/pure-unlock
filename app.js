'use strict';
/*
 * PURE Tuning - Web Bluetooth. Implements the BLE protocol proven from com.zydtech.Pure (ZYD / HobbyWing ESC).
 * Two GATT services: binary DATA (service 0xF1F0, write 0xF1F1, notify 0xF1F2) and ASCII AT CMD (service
 * 0xF2F0, write 0xF2F1, notify 0xF2F2); frame heads 0x01 HEAD_ESC, 0xAB HEAD_MONITOR, 0xA5 HEAD_TRAN;
 * CRC16/MODBUS (poly 0x8005 reflected 0xA001, init 0xFFFF, refin+refout, no xorout) appended little-endian
 * low-byte first; the ESC-command, RW-parameter (0x17) and monitor (0xAB) frame byte layouts; the tuning
 * register map (addr 32 = speed limit x10 max 60 KPH, addr 2 = max modulation depth, addr 23 = wheel
 * diameter x25.4); and the full AT channel (PWD/TYPE/DRIVEMODE/NFC/TLVOICEOFF/SETLUDO) with its OK+/ERR+
 * replies. Auth = optional plaintext PIN (AT+PWD), no crypto pairing. An echo means "accepted" - only
 * on-device behaviour proves a write rode; risky writes are confirm-boxed.
 */

// Pre-commit cache-buster auto-bumps BUILD and every ?v= on any web-asset change.
const BUILD = 'v4';

// --------------------------- UUIDs (Web Bluetooth wants lowercase) ---------------------------
const U = {
  DATA: '0000f1f0-0000-1000-8000-00805f9b34fb',     // DATA_SERVICE - binary data/firmware
  DATA_TX: '0000f1f1-0000-1000-8000-00805f9b34fb',  // DATA_TX  write (binary command/firmware frames)
  DATA_RX: '0000f1f2-0000-1000-8000-00805f9b34fb',  // DATA_RX  notify (binary responses/telemetry)
  CMD: '0000f2f0-0000-1000-8000-00805f9b34fb',      // CMD_SERVICE - ASCII AT commands
  CMD_TX: '0000f2f1-0000-1000-8000-00805f9b34fb',   // CMD_TX  write (ASCII AT)
  CMD_RX: '0000f2f2-0000-1000-8000-00805f9b34fb'    // CMD_RX  notify (ASCII AT responses)
};
const CANDIDATE_SERVICES = [U.DATA, U.CMD];   // both are probed; DATA is the scan filter + the real gate

// --------------------------- protocol constants ---------------------------
const HEAD_ESC = 0x01;       // param/info/firmware command head
const HEAD_MONITOR = 0xAB;   // live settings/limits head
const OP_READ_PARAM = 0x03;  // CMD_READ_PARAMETER
const OP_ESC_INFO = 0x07;    // CMD_ESC_INFO
const OP_BAT_INFO = 0x08;    // CMD_BAT_INFO
const OP_RW_PARAM = 0x17;    // CMD_RW_PARAMETER (used by setAdvParams)
// register addresses (apktool/res/raw/default_parameter.json, mirrored by FullAdvParams)
const REG_SPEED = 32;        // speed limit, scale x10, max 60 KPH
const REG_MODDEPTH = 2;      // max modulation depth, max 50 (top-end)
const REG_WHEEL = 23;        // motor/wheel diameter, scale x25.4 (inch)

// --------------------------- helpers ---------------------------
const $ = (id) => document.getElementById(id);
const hex = (arr) => Array.from(arr, b => (b & 0xff).toString(16).padStart(2, '0').toUpperCase()).join(' ');
const short = (u) => String(u).slice(0, 8).toUpperCase();
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const LS = { THEME: 'pure_theme', OPEN: 'pure_open', EKFV: 'pure_ekfv', PUBLOG: 'pure_publog', DEV: 'pure_device' };

let dev = null, server = null, dataTx = null, dataRx = null, cmdTx = null, cmdRx = null, busy = false;
let connected = false;
let speedUnlocked = false;

// live device state parsed from the ASCII AT channel (unambiguous text).
const S = {
  authType: null, authOk: null, devType: null, driveMode: null, nfc: null, voiceOff: null, ludo: null,
  rxData: 0,
  // binary 0xAB telemetry (null until a frame arrives)
  speed: null, gearPos: null, battery: null, voltage: null, current: null, power: null,
  escTemp: null, motorTemp: null, trip: null, total: null, version: null,
  limCruise: null, limEco: null, limComfort: null, limSport: null
};
// local desired live-settings state for the 0xAB monitor frame. One 0xAB frame always carries ALL of these
// fields together, so writing any one of them rewrites the whole byte from the last chosen values.
const base = { gear: 0, headlight: false, atmosphere: false, cruise: false, bootMode: false, metric: true, lock: false, limitCruise: 0, lm1: 0, lm2: 0, lm3: 0 };
function resetState() {
  S.authType = S.authOk = S.devType = S.driveMode = S.nfc = S.voiceOff = S.ludo = null; S.rxData = 0;
  S.speed = S.gearPos = S.battery = S.voltage = S.current = S.power = null;
  S.escTemp = S.motorTemp = S.trip = S.total = S.version = null;
  S.limCruise = S.limEco = S.limComfort = S.limSport = null;
}

// --------------------------- log (redaction pipeline: scrub secrets + anonymize PII) ---------------------------
let logBuffer = [];   // { raw, cls }
let publicLog = true; // anonymize device name/id/MAC on display/copy/save (default on)
let diag = false;     // verbose diagnostics (default off)
function redact(text) {
  let s = String(text);
  if (dev && dev.id) s = s.split(dev.id).join('[redacted-id]');
  s = s.replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, '[redacted-mac]');
  s = s.replace(/\b(secret|token|key|aes|pwd|password|pin|mac|serial|vin|uid|imei)\b(\s*[:=]\s*)("?)([^\s",]+)\3/gi,
    (m, k, sep) => k + sep + '[redacted]');
  s = s.replace(/\b[0-9A-Fa-f]{16,}\b/g, '[redacted-hex]');
  return s;
}
// PIN scrubber for the ASCII AT channel: the plaintext PIN sits in AT+PWD[..] / AT+PWDM[..] with no key:value
// separator, so maskSecrets below would miss it - blank it here before anything is logged.
function maskAt(text) {
  return String(text).replace(/(AT\+PWDM?\[)[^\]]*(\])/gi, '$1***$2').replace(/(OK\+PWD:)[^\s]*/gi, '$1*');
}
// Unconditional secret scrubber, runs at the source before the buffer (independent of the Public Log toggle).
function maskSecrets(text) {
  let s = maskAt(String(text));
  s = s.replace(/eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g, '[redacted-jwt]');
  s = s.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer ***');
  s = s.replace(/\b(access[_-]?token|refresh[_-]?token|token|jwt|password|passwd|pwd|secret|code|otp)\b(\s*[:=]\s*)("?)([^\s",}]+)\3/gi,
    (m, k, sep) => k + sep + '***');
  return s;
}
function anonymize(s) {
  if (!publicLog) return String(s).replace(/\x01/g, '');
  return redact(String(s).replace(/\x01[^\x01]*\x01/g, 'XX').replace(/\x01/g, ''));
}
function logLine(cls, text) {
  const safe = '[' + new Date().toTimeString().slice(0, 8) + '] ' + maskSecrets(text);
  logBuffer.push({ raw: safe, cls: cls });
  const el = $('log'); if (!el) return;
  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = anonymize(safe) + '\n';
  el.appendChild(span); el.scrollTop = el.scrollHeight;
}
function renderLog() {
  const el = $('log'); if (!el) return;
  el.textContent = '';
  for (const e of logBuffer) { const span = document.createElement('span'); if (e.cls) span.className = e.cls; span.textContent = anonymize(e.raw) + '\n'; el.appendChild(span); }
  el.scrollTop = el.scrollHeight;
}
function logText() { return logBuffer.map(e => anonymize(e.raw)).join('\n'); }
const logTx = (chan, b) => logLine('log-tx', '>>> ' + chan + ' | ' + hex(b));
const logRx = (chan, b) => logLine('log-rx', '<<< ' + chan + ' | ' + hex(b));
const logTxText = (chan, s) => logLine('log-tx', '>>> ' + chan + ' | ' + s);
const logRxText = (chan, s) => logLine('log-rx', '<<< ' + chan + ' | ' + s);
const logSys = (t) => logLine('', '--- ' + t);
const logErr = (t) => logLine('log-err', '!!! ' + t);
const logDiag = (t) => { if (diag) logLine('', '... ' + t); };
// CRLF on Windows so the copied log pastes cleanly into Notepad.
function osNewline() { return (navigator.platform || '').toLowerCase().indexOf('win') === 0 ? '\r\n' : '\n'; }
function saveLog() {
  try {
    const blob = new Blob([logText().split('\n').join(osNewline())], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'laufbursche42-pure-log.txt';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    logSys('log saved');
  } catch (e) { logErr('save failed: ' + (e && e.message ? e.message : e)); }
}
function logDiagnosticHeader() {
  logLine('', '=== pure-unlock diagnostic ===');
  logLine('', 'build: ' + BUILD);
  logLine('', 'time: ' + new Date().toISOString());
  logLine('', 'userAgent: ' + (navigator.userAgent || '?'));
  logLine('', 'platform: ' + (navigator.platform || '?'));
  logLine('', 'webBluetooth: ' + (navigator.bluetooth ? 'yes' : 'no'));
  logLine('', 'protocol self-test: ' + (FRAME_OK ? 'OK' : 'FAILED'));
  logLine('', '================================');
}

// =========================================================================================
//  VERIFIED PROTOCOL CORE (code-proven from com.zydtech.Pure; self-test below runs at load)
// =========================================================================================
// CRC16/MODBUS: reflected poly 0xA001, init 0xFFFF, refin+refout, xorout 0.
function crc16modbus(bytes) {
  let crc = 0xFFFF;
  for (const byte of bytes) {
    crc ^= (byte & 0xff);
    for (let i = 0; i < 8; i++) crc = (crc & 1) ? ((crc >>> 1) ^ 0xA001) : (crc >>> 1);
  }
  return crc & 0xffff;
}
// append the CRC low-byte first (little-endian), as every builder does.
function withCrc(core) { core = core.map(b => b & 0xff); const c = crc16modbus(core); return [...core, c & 0xff, (c >> 8) & 0xff]; }
// ESC command (head 0x01): [0]=0x01 [1]=op [2..3]=addr BE [4..5]=count BE [6..7]=CRC LE
function buildEscCommand(op, addr, count) { return withCrc([HEAD_ESC, op & 0xff, (addr >> 8) & 0xff, addr & 0xff, (count >> 8) & 0xff, count & 0xff]); }
// RW-parameter (op 0x17): [0]=0x01 [1]=0x17 [2..3]=addr BE [4..5]=wc BE [6..7]=addr BE [8..9]=wc BE [10]=byteLen [11..]=value [..]=CRC LE
function buildRwParam(addr, valueBytes) {
  const wc = Math.max(1, Math.ceil(valueBytes.length / 2));   // word count (2 bytes/word)
  return withCrc([HEAD_ESC, OP_RW_PARAM, (addr >> 8) & 0xff, addr & 0xff, (wc >> 8) & 0xff, wc & 0xff,
    (addr >> 8) & 0xff, addr & 0xff, (wc >> 8) & 0xff, wc & 0xff, valueBytes.length & 0xff, ...valueBytes.map(b => b & 0xff)]);
}
const word = (v) => [(v >> 8) & 0xff, v & 0xff];   // 16-bit big-endian register value
// Monitor/live-settings (head 0xAB): [0]=0xAB [1]=0x00 [2]=0x0A [3]=bitfield [4..7]=limitCruise/mode1/2/3 [8..9]=CRC LE
function monitorBitfield() {
  let bf = base.gear & 0x03;                 // b0-1 gear
  if (base.headlight) bf |= 1 << 2;          // b2 headlight
  if (base.atmosphere) bf |= 1 << 3;         // b3 atmosphere light
  if (base.cruise) bf |= 1 << 4;             // b4 cruise
  if (base.bootMode) bf |= 1 << 5;           // b5 boot/zero-start mode
  if (base.metric) bf |= 1 << 6;             // b6 metric (vs imperial)
  if (base.lock) bf |= 1 << 7;               // b7 lock
  return bf & 0xff;
}
function buildMonitor() { return withCrc([HEAD_MONITOR, 0x00, 0x0A, monitorBitfield(), base.limitCruise & 0xff, base.lm1 & 0xff, base.lm2 & 0xff, base.lm3 & 0xff]); }
// strict CRC validator for any binary frame (last 2 bytes = CRC16/MODBUS LE of the rest)
function validFrame(f) {
  if (!f || f.length < 4) return false;
  const c = crc16modbus(f.slice(0, f.length - 2));
  return f[f.length - 2] === (c & 0xff) && f[f.length - 1] === ((c >> 8) & 0xff);
}
// ASCII AT command (CMD channel): plain bytes, no CRC
const encAscii = (s) => Array.from(String(s), c => c.charCodeAt(0) & 0xff);

// --------------------------- telemetry decode (binary 0xAB monitor notifications) ---------------------------
// The scooter pushes two 0xAB notify frames the shared zydtech/HobbyWing parser decodes (proven by parity
// with the byte-identical sibling core; the register scaling is cross-checked against
// apktool/res/raw/default_parameter.json). Subtype at byte[1]: 0x00 = live telemetry, 0x01 = base params.
// The 10-byte 0xAB write-echo (byte[2]=0x0A) is excluded by the length gate below. Scaling constants:
// speed /1000.0, voltage /10.0, current /64.0, mileage /10.0. Bounds-checked reads return null if short.
function u8at(b, i) { return i < b.length ? (b[i] & 0xff) : null; }
function s8at(b, i) { if (i >= b.length) return null; const v = b[i] & 0xff; return v > 127 ? v - 256 : v; }
function u16at(b, i) { if (i + 1 >= b.length) return null; return ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff); }
function s16at(b, i) { const v = u16at(b, i); return v == null ? null : (v > 32767 ? v - 65536 : v); }
function u24at(b, i) { if (i + 2 >= b.length) return null; return ((b[i] & 0xff) << 16) | ((b[i + 1] & 0xff) << 8) | (b[i + 2] & 0xff); }
// 0xAB/00: gear buf[4], battery buf[5], speed max(u16BE@6,u16BE@8)/1000, voltage u16BE@10/10,
// current s16BE@12/64, escTemp s8@14, motorTemp s8@15, trip u16BE@16/10, total u24BE@18/10.
function parseMonitor00(b) {
  S.gearPos = u8at(b, 4);
  S.battery = u8at(b, 5);
  const s6 = u16at(b, 6), s8v = u16at(b, 8);
  S.speed = (s6 == null && s8v == null) ? null : Math.max(s6 || 0, s8v || 0) / 1000;
  const v = u16at(b, 10); S.voltage = (v == null) ? null : v / 10;
  const c = s16at(b, 12); S.current = (c == null) ? null : c / 64;
  S.escTemp = s8at(b, 14);
  S.motorTemp = s8at(b, 15);
  const tr = u16at(b, 16); S.trip = (tr == null) ? null : tr / 10;
  const to = u24at(b, 18); S.total = (to == null) ? null : to / 10;
  S.power = (S.voltage != null && S.current != null) ? (S.voltage * S.current) : null;
}
// 0xAB/01: limitCruise buf[3], limitMode1/2/3 buf[4..6] (km/h, Eco/Comfort/Sport), version buf[20..22].
function parseMonitor01(b) {
  S.limCruise = u8at(b, 3);
  S.limEco = u8at(b, 4);
  S.limComfort = u8at(b, 5);
  S.limSport = u8at(b, 6);
  const a = u8at(b, 20), m = u8at(b, 21), p = u8at(b, 22);
  S.version = (a == null || m == null || p == null) ? null : ('V' + a + '.' + m + '.' + p);
}

// load-time self-test: builders must match hand-computed vectors and the canonical CRC16/MODBUS check value.
const FRAME_OK = (function () {
  const eq = (a, b) => a.length === b.length && a.every((v, i) => (v & 0xff) === (b[i] & 0xff));
  const crcCanon = crc16modbus(encAscii('123456789')) === 0x4B37;       // canonical CRC-16/MODBUS check value
  const t1 = eq(buildEscCommand(OP_BAT_INFO, 0, 7), [0x01, 0x08, 0x00, 0x00, 0x00, 0x07, 0xA1, 0xC9]);
  const t2 = eq(buildMonitor(), [0xAB, 0x00, 0x0A, 0x40, 0x00, 0x00, 0x00, 0x00, 0x0A, 0xA5]); // base.metric default (bitfield 0x40)
  const t3 = eq(buildRwParam(REG_SPEED, word(200)), [0x01, 0x17, 0x00, 0x20, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x02, 0x00, 0xC8, 0x53, 0x32]);
  // decode vectors: a synthetic 0xAB/00 live frame and 0xAB/01 base frame (CRC-sealed) must parse to known values.
  const save = {}; for (const k in S) save[k] = S[k];
  const f00 = withCrc([0xAB, 0x00, 0x00, 0x00, 0x02, 0x50, 0x61, 0xA8, 0x00, 0x00, 0x01, 0xE0, 0x02, 0x80, 0x28, 0x32, 0x00, 0x7B, 0x00, 0x03, 0xE8, 0x00, 0x00]);
  parseMonitor00(f00);
  const d00 = S.gearPos === 2 && S.battery === 80 && S.speed === 25 && S.voltage === 48 && S.current === 10 && S.escTemp === 40 && S.motorTemp === 50 && S.trip === 12.3 && S.total === 100;
  const f01 = withCrc([0xAB, 0x01, 0x00, 0x14, 0x0F, 0x14, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03]);
  parseMonitor01(f01);
  const d01 = S.limCruise === 20 && S.limEco === 15 && S.limComfort === 20 && S.limSport === 25 && S.version === 'V1.2.3';
  for (const k in save) S[k] = save[k];
  return crcCanon && t1 && t2 && t3 && d00 && d01 && validFrame(buildEscCommand(OP_ESC_INFO, 0, 5)) && validFrame(buildMonitor());
})();

// AT response parser (ASCII lines "OK+KEY:val" / "ERR+KEY"); updates S from reliable text.
function parseAtLine(line) {
  const s = String(line).trim(); if (!s) return;
  let m;
  if ((m = s.match(/OK\+TYPE:([AB])/i))) S.authType = m[1].toUpperCase();
  else if ((m = s.match(/OK\+PWD:([YN])/i))) S.authOk = (m[1].toUpperCase() === 'Y');
  else if ((m = s.match(/OK\+DRIVEMODE:(\d+)/i))) S.driveMode = parseInt(m[1], 10);
  else if ((m = s.match(/OK\+NFC:(\d+)/i))) S.nfc = parseInt(m[1], 10);
  else if ((m = s.match(/OK\+TLVOICEOFF:(\d+)/i))) S.voiceOff = parseInt(m[1], 10);
  else if ((m = s.match(/OK\+SETLUDO:(\d+)/i))) S.ludo = parseInt(m[1], 10);
  else if ((m = s.match(/OK\+DEVICE[:\s]?(.+)$/i))) S.devType = m[1].trim();
  resolveAck('at:' + s.replace(/[:\d].*$/, ''));   // loose key for arming (e.g. OK+NFC)
}

// --------------------------- tiles ---------------------------
const TILE_IDS = ['t-devtype', 't-auth', 't-drivemode', 't-nfc', 't-voice', 't-ludo', 't-rxframes',
  't-speed', 't-gearpos', 't-esctemp', 't-motortemp', 't-trip', 't-total', 't-version',
  't-lim-cruise', 't-lim-eco', 't-lim-comfort', 't-lim-sport',
  't-batt-soc', 't-batt-volt', 't-batt-curr', 't-batt-power'];
function setTile(id, val) { const el = $(id); if (el) el.textContent = (val == null ? '-' : val); }
function resetTiles() { TILE_IDS.forEach(id => setTile(id, null)); }
function onOff(v) { return v == null ? null : (v ? t('valOn') : t('valOff')); }
// locale number: German decimals use a comma (matches the rest of the de UI).
function num(v, dp) { if (v == null) return null; const s = Number(v).toFixed(dp); return lang === 'de' ? s.replace('.', ',') : s; }
function refreshTiles() {
  setTile('t-devtype', S.devType == null ? null : S.devType);
  setTile('t-auth', S.authType == null ? null : (S.authType === 'B' ? t('valPwdReq') : t('valPwdNo')));
  setTile('t-drivemode', S.driveMode == null ? null : (S.driveMode ? t('valDual') : t('valSingle')));
  setTile('t-nfc', onOff(S.nfc));
  setTile('t-voice', onOff(S.voiceOff));
  setTile('t-ludo', onOff(S.ludo));
  setTile('t-rxframes', S.rxData ? String(S.rxData) : null);
  // binary 0xAB telemetry tiles
  setTile('t-speed', S.speed == null ? null : num(S.speed, 1) + ' km/h');
  setTile('t-gearpos', S.gearPos == null ? null : String(S.gearPos));
  setTile('t-esctemp', S.escTemp == null ? null : S.escTemp + ' °C');
  setTile('t-motortemp', S.motorTemp == null ? null : S.motorTemp + ' °C');
  setTile('t-trip', S.trip == null ? null : num(S.trip, 1) + ' km');
  setTile('t-total', S.total == null ? null : num(S.total, 1) + ' km');
  setTile('t-version', S.version == null ? null : S.version);
  setTile('t-lim-cruise', S.limCruise == null ? null : S.limCruise + ' km/h');
  setTile('t-lim-eco', S.limEco == null ? null : S.limEco + ' km/h');
  setTile('t-lim-comfort', S.limComfort == null ? null : S.limComfort + ' km/h');
  setTile('t-lim-sport', S.limSport == null ? null : S.limSport + ' km/h');
  setTile('t-batt-soc', S.battery == null ? null : S.battery + ' %');
  setTile('t-batt-volt', S.voltage == null ? null : num(S.voltage, 1) + ' V');
  setTile('t-batt-curr', S.current == null ? null : num(S.current, 1) + ' A');
  setTile('t-batt-power', S.power == null ? null : num(S.power, 1) + ' W');
}

// --------------------------- i18n ---------------------------
let lang = 'de';
function table() { return (window.I18N && window.I18N[lang]) || {}; }
function t(key) { const v = table()[key]; return (typeof v === 'string') ? v : ''; }
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-t]').forEach(n => { const v = t(n.getAttribute('data-t')); if (/[<&]/.test(v)) n.innerHTML = v; else n.textContent = v; }); // scan-ok: curated i18n values with markup (banner/disclaimer links); own table, not user input
  document.querySelectorAll('[data-t-ph]').forEach(n => { const v = t(n.getAttribute('data-t-ph')); if (v) n.setAttribute('placeholder', v); });
  ['GUIDE', 'README', 'LICENSE', 'PRIVACY', 'TRADEMARKS'].forEach(name => { const el = $('link-' + name.toLowerCase()); if (el) el.href = docFile(name); });
  { const el = $('langs'); if (el) el.setAttribute('aria-label', t('langGroup')); }
  { const el = $('build-ver'); if (el) el.textContent = t('buildLabel') + ' ' + BUILD; }
  document.querySelectorAll('#langs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
  refreshTiles(); updateToggleButton(); updateAuthUI();
  { const el = $('status'); setStatus(el ? el.dataset.state : 'disconnected'); }
  { const dark = document.documentElement.getAttribute('data-theme') !== 'light'; const el = $('btn-theme'); if (el) { el.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); el.title = el.getAttribute('aria-label'); } }
}
function initLangSwitch() { document.querySelectorAll('#langs button').forEach(b => b.addEventListener('click', () => { lang = b.dataset.lang; applyLang(); })); }

// --------------------------- theme ---------------------------
function applyTheme(dark) {
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  const b = $('btn-theme');
  if (b) { b.textContent = dark ? '\u2600' : '\u263E'; b.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); b.title = b.getAttribute('aria-label'); }
  try { localStorage.setItem(LS.THEME, dark ? 'dark' : 'light'); } catch (e) {}
}
function initTheme() {
  let saved = null; try { saved = localStorage.getItem(LS.THEME); } catch (e) {}
  applyTheme(saved !== 'light');
  const b = $('btn-theme'); if (b) b.addEventListener('click', () => applyTheme(document.documentElement.getAttribute('data-theme') === 'light'));
}

// --------------------------- status ---------------------------
function statusLabel(s) {
  const map = { disconnected: 'stDisconnected', connecting: 'stConnecting', linking: 'stLinking', connected: 'stConnected', 'no-service': 'stNoService' };
  return t(map[s] || 'stDisconnected') || s;
}
function setStatus(s) {
  const el = $('status'); if (el) { el.dataset.state = s; el.textContent = statusLabel(s); }
  const cb = $('btn-conn');
  if (cb) { const on = (s === 'connecting' || s === 'linking' || s === 'connected'); cb.textContent = on ? t('btnDisconnect') : t('btnConnect'); cb.dataset.act = on ? 'disconnect' : 'connect'; }
}
function setControlsEnabled(on) {
  // control cards hidden until connected (header/intro/connect/log stay visible)
  ['live-card', 'batt-card', 'more-card', 'raw-card'].forEach(id => { const el = $(id); if (el) el.hidden = !on; });
  document.querySelectorAll('[data-conn]').forEach(e => { e.disabled = !on; });
}

// --------------------------- connect (acceptAll or service filter; GATT service is the real gate; 4x retry) ---------------------------
async function connect() {
  if (!navigator.bluetooth) { logErr(t('errNoWebBt')); return; }
  try {
    setStatus('connecting');
    const showAll = ($('showall') || {}).checked;
    const opts = showAll
      ? { acceptAllDevices: true, optionalServices: CANDIDATE_SERVICES }
      : { filters: [{ services: [U.DATA] }], optionalServices: CANDIDATE_SERVICES };
    dev = await navigator.bluetooth.requestDevice(opts);
    dev.addEventListener('gattserverdisconnected', onDisconnected);
    try { localStorage.setItem(LS.DEV, dev.id); } catch (e) {}
    logSys('device: \x01' + (dev.name || '(no name)') + '\x01');
    setStatus('linking');
    await connectGatt();
    setStatus('connected'); connected = true;
    setControlsEnabled(true);
    { const el = $('devinfo'); if (el) el.textContent = t('devPrefix') + ' \x01' + (dev.name || 'PURE') + '\x01'; }
    logSys('connected; data=' + short(U.DATA_RX) + (cmdRx ? ' cmd=' + short(U.CMD_RX) : ' (no AT service)'));
    await afterConnect();
  } catch (e) {
    logErr('connect failed: ' + (e && e.message ? e.message : e));
    connected = false; setStatus('disconnected'); setControlsEnabled(false);
  }
}
// tolerate the Android discovery race (4x retry): services can be briefly absent right after link.
async function connectGatt() {
  let lastErr = null;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      server = await dev.gatt.connect();
      const dataSvc = await getService(server, U.DATA);
      if (!dataSvc) { setStatus('no-service'); throw new Error('PURE data service ' + short(U.DATA) + ' not found'); }
      dataTx = await dataSvc.getCharacteristic(U.DATA_TX);
      dataRx = await dataSvc.getCharacteristic(U.DATA_RX);
      await dataRx.startNotifications();
      dataRx.addEventListener('characteristicvaluechanged', onDataValue);
      // AT command service is best-effort: present on most units, absent on a few; data channel still works.
      cmdTx = cmdRx = null;
      try {
        const cmdSvc = await getService(server, U.CMD);
        if (cmdSvc) {
          cmdTx = await cmdSvc.getCharacteristic(U.CMD_TX);
          cmdRx = await cmdSvc.getCharacteristic(U.CMD_RX);
          await cmdRx.startNotifications();
          cmdRx.addEventListener('characteristicvaluechanged', onCmdValue);
        }
      } catch (e) { logDiag('AT command service unavailable: ' + (e && e.message ? e.message : e)); }
      return;
    } catch (e) {
      lastErr = e; logDiag('connect attempt ' + attempt + ' failed: ' + (e && e.message ? e.message : e));
      try { if (dev.gatt.connected) dev.gatt.disconnect(); } catch (_) {}
      await sleep(400);
    }
  }
  throw lastErr || new Error('gatt connect failed');
}
async function getService(srv, uuid) { try { return await srv.getPrimaryService(uuid); } catch (_) { return null; } }
// post-connect: query the ASCII AT state, and trigger an ESC-info read frame.
async function afterConnect() {
  if (cmdTx) {
    for (const q of ['AT+TYPE?', 'AT+DEVICE?', 'AT+DRIVEMODE?', 'AT+NFC?', 'AT+TLVOICEOFF?', 'AT+SETLUDO:?']) { await transmitAt(q, q); await sleep(120); }
  }
  try { await transmit('data', buildEscCommand(OP_ESC_INFO, 0, 5), t('readInfo')); } catch (e) {}
  updateAuthUI();
}
function onDisconnected() {
  connected = false; dataTx = dataRx = cmdTx = cmdRx = null; setStatus('disconnected'); setControlsEnabled(false);
  resetState(); resetTiles(); clearAcks();
  updateToggleButton(); updateAuthUI();
  const el = $('devinfo'); if (el) el.textContent = '';
  logSys('disconnected');
}
function disconnect() { if (dev && dev.gatt.connected) dev.gatt.disconnect(); }

// --------------------------- notify (binary DATA + ASCII CMD) + ACK ---------------------------
function onDataValue(ev) {
  const b = Array.from(new Uint8Array(ev.target.value.buffer));
  logRx(short(U.DATA_RX), b);
  S.rxData++;
  // decode the pushed 0xAB monitor notifications; the short write-echo (len 10) fails the length gate.
  if (validFrame(b) && b[0] === HEAD_MONITOR && b.length >= 23) {
    if (b[1] === 0x00) parseMonitor00(b);
    else if (b[1] === 0x01) parseMonitor01(b);
  }
  refreshTiles();
}
function onCmdValue(ev) {
  const bytes = new Uint8Array(ev.target.value.buffer);
  let s = ''; for (const c of bytes) s += String.fromCharCode(c);
  logRxText(short(U.CMD_RX), maskAt(s.replace(/[\r\n]+/g, ' ').trim()));
  for (const line of s.split(/[\r\n]+/)) parseAtLine(line);
  refreshTiles(); updateAuthUI();
}
const pendingAcks = new Map();
const ACK_TIMEOUT_MS = 3000;
function armAck(key, label) {
  clearAckTimer(key);
  const timer = setTimeout(() => { pendingAcks.delete(key); logSys(label + ': ' + t('ackNone')); }, ACK_TIMEOUT_MS);
  pendingAcks.set(key, { timer, label });
}
function resolveAck(key) { const a = pendingAcks.get(key); if (a) { clearTimeout(a.timer); pendingAcks.delete(key); logSys(a.label + ': ' + t('ackOk')); } }
function clearAckTimer(key) { const a = pendingAcks.get(key); if (a) { clearTimeout(a.timer); pendingAcks.delete(key); } }
function clearAcks() { for (const a of pendingAcks.values()) clearTimeout(a.timer); pendingAcks.clear(); }

// --------------------------- transmit (channel-aware funnel: log TX, arm ack, write) ---------------------------
async function writeChar(chObj, arr) {
  if (chObj.properties.write) return chObj.writeValueWithResponse(arr);
  if (chObj.properties.writeWithoutResponse) return chObj.writeValueWithoutResponse(arr);
  return chObj.writeValue(arr);
}
// binary DATA channel.
async function transmit(chan, bytes, label, ackKey) {
  if (!connected || !dataTx) { logErr(t('errNotConnected')); return; }
  const arr = Uint8Array.from(bytes);
  logTx(short(U.DATA_TX), bytes);
  if (ackKey) armAck(ackKey, label);
  try { await writeChar(dataTx, arr); logSys(label + ': ' + t('txSent')); }
  catch (e) { clearAckTimer(ackKey); logErr(label + ' ' + t('txFailed') + ': ' + (e && e.message ? e.message : e)); }
}
// ASCII AT channel. Arms an ack on the command key; the OK+ reply resolves it.
async function transmitAt(text, label) {
  if (!connected) { logErr(t('errNotConnected')); return; }
  if (!cmdTx) { logErr(t('errNoAt')); return; }
  const key = 'at:' + String(text).replace(/[\[\?:].*$/, '');
  logTxText(short(U.CMD_TX), maskAt(text));
  armAck(key, label);
  try { await writeChar(cmdTx, Uint8Array.from(encAscii(text))); logSys(label + ': ' + t('txSent')); }
  catch (e) { clearAckTimer(key); logErr(label + ' ' + t('txFailed') + ': ' + (e && e.message ? e.message : e)); }
}
// serialize writes
async function guard(fn) { if (busy) return; busy = true; try { await fn(); } catch (e) { logErr(e && e.message ? e.message : String(e)); } finally { busy = false; } }

// --------------------------- commands ---------------------------
async function sendMonitor(label) { await transmit('data', buildMonitor(), label); }   // one 0xAB frame = ALL live-settings fields
async function setSpeed(kmh) {
  const v = Math.max(1, Math.min(60, kmh | 0));
  await transmit('data', buildRwParam(REG_SPEED, word(v * 10)), t('speedLabel') + ' ' + v + ' km/h');   // addr 32, scale x10
}

// --------------------------- speed card (toggle open <-> eKFV) ---------------------------
function openSpeedValue() { const v = parseInt(($('speed-in') || {}).value, 10); return isNaN(v) ? 40 : v; }
function ekfvSpeedValue() { const v = parseInt(($('ekfv-in') || {}).value, 10); return isNaN(v) ? 20 : v; }
function updateToggleButton() { const b = $('btn-toggle'); if (b) b.textContent = speedUnlocked ? t('btnLock') : t('btnUnlock'); }
async function doSpeedToggle() {
  const v = speedUnlocked ? ekfvSpeedValue() : openSpeedValue();
  if (!(v >= 1 && v <= 60)) { logErr(t('errSpeedRange')); return; }
  if (!await confirmRisky(t('warnSpeed'))) return;
  await setSpeed(v);
  speedUnlocked = !speedUnlocked;
  updateToggleButton();
}

// --------------------------- auth (optional plaintext PIN over the AT channel) ---------------------------
function updateAuthUI() {
  const el = $('auth-current'); if (!el) return;
  if (!connected) { el.textContent = ''; return; }
  if (!cmdTx) { el.textContent = t('authNoAt'); return; }
  if (S.authType == null) el.textContent = t('authUnknown');
  else if (S.authType === 'A') el.textContent = t('authNone');
  else el.textContent = (S.authOk === true) ? t('authOk') : (S.authOk === false ? t('authBad') : t('authNeed'));
}
async function sendPin() {
  const pin = String(($('pin-in') || {}).value || '').replace(/[^0-9A-Za-z]/g, '');
  if (!pin) { logErr(t('errNoPin')); return; }
  await transmitAt('AT+PWD[' + pin + ']', t('lblPin'));
}

// --------------------------- Weitere Einstellungen (static rows, one Senden button each) ---------------------------
// row.k -> select id "<k>-in" + button id "btn-<k>". Risky rows ask for confirmation first.
const SETTINGS = [
  { k: 'drivemode', apply: v => transmitAt('AT+DRIVEMODE[' + v + ']', t('set_drivemode')) },
  { k: 'gear', risky: true, warnKey: 'warnMonitor', apply: v => { base.gear = v & 0x03; return sendMonitor(t('set_gear')); } },
  { k: 'cruise', risky: true, warnKey: 'warnMonitor', apply: v => { base.cruise = !!v; return sendMonitor(t('set_cruise')); } },
  { k: 'zerostart', risky: true, warnKey: 'warnMonitor', apply: v => { base.bootMode = !!v; return sendMonitor(t('set_zerostart')); } },
  { k: 'light', risky: true, warnKey: 'warnMonitor', apply: v => { base.headlight = !!v; return sendMonitor(t('set_light')); } },
  { k: 'atmos', risky: true, warnKey: 'warnMonitor', apply: v => { base.atmosphere = !!v; return sendMonitor(t('set_atmos')); } },
  { k: 'unit', risky: true, warnKey: 'warnMonitor', apply: v => { base.metric = (v === 0); return sendMonitor(t('set_unit')); } },
  { k: 'nfc', apply: v => transmitAt('AT+NFC[' + v + ']', t('set_nfc')) },
  { k: 'voice', apply: v => transmitAt('AT+TLVOICEOFF[' + v + ']', t('set_voice')) },
  { k: 'ludo', apply: v => transmitAt('AT+SETLUDO[' + v + ']', t('set_ludo')) },
  { k: 'lock', risky: true, warnKey: 'warnLock', apply: v => { base.lock = !!v; return sendMonitor(t('set_lock')); } },
  { k: 'wheel', risky: true, warnKey: 'warnWheel', vals: [85, 100, 110], apply: (v, r) => transmit('data', buildRwParam(REG_WHEEL, word(Math.round((r.vals[v] / 10) * 25.4))), t('set_wheel')) },
  { k: 'moddepth', risky: true, warnKey: 'warnMod', vals: [30, 40, 50], apply: (v, r) => transmit('data', buildRwParam(REG_MODDEPTH, word(r.vals[v])), t('set_moddepth')) }
];
function wireSettings() {
  for (const s of SETTINGS) {
    const btn = $('btn-' + s.k), sel = $(s.k + '-in'); if (!btn || !sel) continue;
    btn.addEventListener('click', () => guard(async () => {
      const v = parseInt(sel.value, 10) || 0;
      if (s.risky && !await confirmRisky(t(s.warnKey))) return;
      await s.apply(v, s);
    }));
  }
}

// --------------------------- Erweiterte Einstellungen (engine level) ---------------------------
function hexToBytes(s) {
  const clean = String(s).replace(/[^0-9a-fA-F]/g, '');   // strip spaces/punctuation
  const out = []; for (let i = 0; i + 2 <= clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));   // pairs; drop a dangling nibble
  return out;
}
function parseWords(s) {
  return String(s).split(/[,\s]+/).map(x => parseInt(x, 10)).filter(v => !isNaN(v));
}
async function cmdRegRead() {
  const addr = parseInt(($('reg-addr-in') || {}).value, 10);
  if (isNaN(addr)) { logErr(t('errBadAddr')); return; }
  await transmit('data', buildEscCommand(OP_READ_PARAM, addr, 1), t('readLabel') + ' ' + addr);
}
async function cmdRegWrite() {
  const addr = parseInt(($('reg-addr-in') || {}).value, 10);
  const vals = parseWords(($('reg-values-in') || {}).value || '');
  if (isNaN(addr)) { logErr(t('errBadAddr')); return; }
  if (!vals.length) { logErr(t('errNoValues')); return; }
  if (!await confirmRisky(t('warnRaw'))) return;
  const bytes = []; vals.forEach(v => bytes.push((v >> 8) & 0xff, v & 0xff));
  await transmit('data', buildRwParam(addr, bytes), t('regLabel') + ' ' + addr);
}
async function cmdRaw() {
  const bytes = hexToBytes(($('raw-in') || {}).value || '');
  if (!bytes.length) { logErr(t('errNoBytes')); return; }
  if (!await confirmRisky(t('warnRaw'))) return;
  const chan = (($('raw-chan') || {}).value === 'cmd') ? 'cmd' : 'data';
  if (chan === 'cmd') {
    if (!cmdTx) { logErr(t('errNoAt')); return; }
    logTx(short(U.CMD_TX), bytes);
    try { await writeChar(cmdTx, Uint8Array.from(bytes)); logSys(t('rawLabel') + ': ' + t('txSent')); } catch (e) { logErr(t('rawLabel') + ' ' + t('txFailed') + ': ' + (e && e.message ? e.message : e)); }
  } else {
    await transmit('data', bytes, t('rawLabel'));   // sent verbatim, no CRC added
  }
}
async function cmdFree() {
  const op = parseInt(($('free-op') || {}).value, 16);
  if (isNaN(op)) { logErr(t('errBadOp')); return; }
  const payload = hexToBytes(($('free-payload') || {}).value || '');
  if (!await confirmRisky(t('warnRaw'))) return;
  // build a proper head-0x01 ESC frame: [0x01, op, ...payload, CRC LE]
  await transmit('data', withCrc([HEAD_ESC, op & 0xff, ...payload]), t('freeLabel') + ' 0x' + (op & 0xff).toString(16));
}
async function cmdAt() {
  const line = String(($('at-in') || {}).value || '').trim();
  if (!line) { logErr(t('errNoAt')); return; }
  await transmitAt(line, t('atLabel'));
}

// --------------------------- confirm dialog (themed; window.confirm fallback) ---------------------------
function confirmRisky(msg) {
  return new Promise(resolve => {
    const dlg = $('confirm'); const body = $('confirm-body');
    if (!dlg || !dlg.showModal) { resolve(window.confirm(msg)); return; }
    if (body) body.textContent = msg;
    const ok = $('confirm-ok'), cancel = $('confirm-x'), no = $('confirm-no');
    const done = (v) => { dlg.close(); ok.removeEventListener('click', onOk); if (no) no.removeEventListener('click', onNo); if (cancel) cancel.removeEventListener('click', onNo); resolve(v); };
    const onOk = () => done(true), onNo = () => done(false);
    ok.addEventListener('click', onOk); if (no) no.addEventListener('click', onNo); if (cancel) cancel.addEventListener('click', onNo);
    dlg.showModal();
  });
}

// --------------------------- doc viewer (markdown of our own docs) ---------------------------
const DOC_TITLES = { 'GUIDE.de.md': 'footGuide', 'GUIDE.en.md': 'footGuide', 'README.md': 'footReadme', 'LICENSE.de.md': 'footLicense', 'LICENSE.md': 'footLicense', 'PRIVACY.de.md': 'footPrivacy', 'PRIVACY.md': 'footPrivacy', 'TRADEMARKS.de.md': 'footTrademarks', 'TRADEMARKS.md': 'footTrademarks' };
const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const slug = s => s.toLowerCase().trim().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-');
function docFile(name) { if (name === 'README') return 'README.md'; if (name === 'GUIDE') return 'GUIDE.' + lang + '.md'; return name + (lang === 'de' ? '.de.md' : '.md'); }
function mdToHtml(src) {
  const inline = s => escHtml(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (all, text, href) => DOC_TITLES[href] ? '<a href="' + href + '" data-docfile="' + href + '">' + text + '</a>' : '<a href="' + href + '" target="_blank" rel="noopener">' + text + '</a>');
  const lines = String(src).split(/\r?\n/); let html = '', inList = false, inCode = false;
  for (const ln of lines) {
    if (/^```/.test(ln)) { if (inCode) { html += '</pre>'; inCode = false; } else { if (inList) { html += '</ul>'; inList = false; } html += '<pre class="doc-code">'; inCode = true; } continue; }
    if (inCode) { html += escHtml(ln) + '\n'; continue; }
    const h = ln.match(/^(#{1,4})\s+(.*)$/);
    if (h) { if (inList) { html += '</ul>'; inList = false; } const lvl = h[1].length + 1; html += '<h' + lvl + ' id="' + slug(h[2]) + '">' + inline(h[2]) + '</h' + lvl + '>'; continue; }
    const li = ln.match(/^\s*[-*]\s+(.*)$/);
    if (li) { if (!inList) { html += '<ul>'; inList = true; } html += '<li>' + inline(li[1]) + '</li>'; continue; }
    if (/^\s*$/.test(ln)) { if (inList) { html += '</ul>'; inList = false; } continue; }
    if (inList) { html += '</ul>'; inList = false; }
    html += '<p>' + inline(ln) + '</p>';
  }
  if (inList) html += '</ul>'; if (inCode) html += '</pre>';
  return html;
}
const docCache = {};
async function openDocFile(file) {
  const dlg = $('doc'); const titleEl = $('doc-title'); const bodyEl = $('doc-body');
  titleEl.textContent = t(DOC_TITLES[file] || 'footReadme');
  if (lang === 'de' && /\.md$/.test(file) && !/\.de\.md$/.test(file) && file !== 'README.md') titleEl.textContent += ' (englisch)';
  try { if (!docCache[file]) { const r = await fetch(file); docCache[file] = await r.text(); } bodyEl.innerHTML = mdToHtml(docCache[file]); } // scan-ok: own in-repo markdown rendered via mdToHtml; not user input
  catch (e) { bodyEl.textContent = 'Could not load ' + file; }
  if (dlg.showModal) dlg.showModal();
}
function wireDocViewer() {
  document.addEventListener('click', e => {
    const d = e.target.closest('a[data-doc]'); if (d) { e.preventDefault(); openDocFile(docFile(d.getAttribute('data-doc'))); return; }
    const df = e.target.closest('a[data-docfile]'); if (df) { e.preventDefault(); openDocFile(df.getAttribute('data-docfile')); return; }
    const disc = e.target.closest('[data-open-disclaimer]'); if (disc) { e.preventDefault(); openHelpText(t('footDisclaimer'), t('disclaimerText')); return; }
  });
  ['doc-x', 'doc-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', () => $('doc').close()); });
}

// --------------------------- help modal ---------------------------
function openHelp(key) { openHelpText(t('help_' + key + '_t'), t('help_' + key + '_b')); }
function openHelpText(title, body) {
  const dlg = $('help'); $('help-title').textContent = title || ''; const b = $('help-body'); if (/[<&]/.test(body || '')) b.innerHTML = body; else b.textContent = body || ''; // scan-ok: curated i18n help text; own table, not user input
  if (dlg.showModal) dlg.showModal();
}
function closeHelp() { const d = $('help'); if (d) d.close(); }

// --------------------------- init ---------------------------
window.addEventListener('DOMContentLoaded', () => {
  initLangSwitch(); initTheme(); wireDocViewer(); wireSettings();
  try { const o = localStorage.getItem(LS.OPEN); if (o && $('speed-in')) $('speed-in').value = o; } catch (e) {}
  try { const k = localStorage.getItem(LS.EKFV); if (k && $('ekfv-in')) $('ekfv-in').value = k; } catch (e) {}
  applyLang(); setStatus('disconnected'); resetTiles();
  logDiagnosticHeader();
  if (!FRAME_OK) logErr('protocol self-test FAILED - builders do not match known vectors; do not trust writes');

  $('btn-conn').addEventListener('click', () => { if ($('btn-conn').dataset.act === 'disconnect') disconnect(); else guard(connect); });
  { const b = $('btn-pin'); if (b) b.addEventListener('click', () => guard(sendPin)); }
  { const o = $('speed-in'); if (o) o.addEventListener('change', () => { try { localStorage.setItem(LS.OPEN, o.value); } catch (e) {} }); }
  { const k = $('ekfv-in'); if (k) k.addEventListener('change', () => { try { localStorage.setItem(LS.EKFV, k.value); } catch (e) {} }); }

  { const b = $('btn-toggle'); if (b) b.addEventListener('click', () => guard(doSpeedToggle)); }

  { const b = $('btn-reg-read'); if (b) b.addEventListener('click', () => guard(cmdRegRead)); }
  { const b = $('btn-reg-write'); if (b) b.addEventListener('click', () => guard(cmdRegWrite)); }
  { const b = $('btn-raw'); if (b) b.addEventListener('click', () => guard(cmdRaw)); }
  { const b = $('btn-free'); if (b) b.addEventListener('click', () => guard(cmdFree)); }
  { const b = $('btn-at'); if (b) b.addEventListener('click', () => guard(cmdAt)); }

  document.querySelectorAll('.help-btn[data-help]').forEach(btn => btn.addEventListener('click', () => openHelp(btn.getAttribute('data-help'))));
  ['help-x', 'help-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', closeHelp); });
  { const b = $('link-disclaimer'); if (b) b.addEventListener('click', e => { e.preventDefault(); openHelpText(t('footDisclaimer'), t('disclaimerText')); }); }

  { const cb = $('public-log'); if (cb) { let saved = null; try { saved = localStorage.getItem(LS.PUBLOG); } catch (e) {} publicLog = saved !== '0'; cb.checked = publicLog; cb.addEventListener('change', () => { publicLog = cb.checked; try { localStorage.setItem(LS.PUBLOG, cb.checked ? '1' : '0'); } catch (e) {} logSys('public-log: ' + (cb.checked ? 'on (anonymizing device name/id)' : 'off')); renderLog(); }); } }
  { const cb = $('diag-log'); if (cb) { cb.addEventListener('change', () => { diag = cb.checked; logSys(diag ? 'diagnostic log on' : 'diagnostic log off'); }); } }
  { const cb = $('showall'); if (cb) { cb.addEventListener('change', () => { logSys('show-all-frames: ' + (cb.checked ? 'on' : 'off')); renderLog(); }); } }
  { const b = $('btn-clear-log'); if (b) b.addEventListener('click', () => { logBuffer = []; $('log').textContent = ''; logDiagnosticHeader(); }); }
  { const b = $('btn-copy-log'); if (b) b.addEventListener('click', () => navigator.clipboard.writeText(logText()).then(() => logSys('log copied')).catch(() => {})); }
  { const b = $('btn-save-log'); if (b) b.addEventListener('click', saveLog); }
});
