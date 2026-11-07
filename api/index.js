// file: api/index.js
// runtime: Vercel Serverless Node.js 18+ / 20+ / 22+
// env: EXTRACTOR_API_KEY (REQUIRED — no default; /api/extract returns 503 when unset)

const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const initSqlJs = require('sql.js');

const API_KEY = process.env.EXTRACTOR_API_KEY || '';
const MAX_BODY_BYTES = 32 * 1024 * 1024; // hard cap for the raw request body
const MAX_SQLITE_BYTES = 25 * 1024 * 1024; // hard cap for the decoded Login Data file

function keyMatches(clientKey) {
    if (!API_KEY || !clientKey || typeof clientKey !== 'string') return false;
    const a = Buffer.from(clientKey, 'utf8');
    const b = Buffer.from(API_KEY, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

// Best-effort per-IP rate limit (per serverless instance)
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX_PER_WINDOW = 20;
const rateBuckets = new Map();
function isRateLimited(ip) {
    const now = Date.now();
    let bucket = rateBuckets.get(ip);
    if (!bucket || now - bucket.start >= RATE_WINDOW_MS) {
        bucket = { start: now, count: 0 };
        rateBuckets.set(ip, bucket);
    }
    bucket.count += 1;
    if (rateBuckets.size > 5000) rateBuckets.clear();
    return bucket.count > RATE_MAX_PER_WINDOW;
}

// ---------------------------------------------------------------------------
// CHROME ELEVATION SERVICE CONSTANTS (v127 -> v135+)
// ---------------------------------------------------------------------------
const KEY_FLAG1_AES = Buffer.from(
    'B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787',
    'hex'
);
const KEY_FLAG2_CHACHA = Buffer.from(
    'E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660',
    'hex'
);
const KEY_FLAG3_XOR = Buffer.from(
    'CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390',
    'hex'
);

let SQL_PROMISE = null;
function getSqlEngine() {
    if (!SQL_PROMISE) {
        SQL_PROMISE = (async () => {
            try {
                // Try locating wasm file in node_modules or relative directories
                const possiblePaths = [
                    path.join(__dirname, '..', 'node_modules', 'sql.js', 'dist', 'sql-wasm.wasm'),
                    path.join(process.cwd(), 'node_modules', 'sql.js', 'dist', 'sql-wasm.wasm'),
                    path.join('/var/task', 'node_modules', 'sql.js', 'dist', 'sql-wasm.wasm'),
                ];
                let wasmBinary = null;
                for (const p of possiblePaths) {
                    if (fs.existsSync(p)) {
                        wasmBinary = fs.readFileSync(p);
                        break;
                    }
                }
                if (!wasmBinary) {
                    const resolved = require.resolve('sql.js');
                    const wasmPath = path.join(path.dirname(resolved), 'sql-wasm.wasm');
                    if (fs.existsSync(wasmPath)) wasmBinary = fs.readFileSync(wasmPath);
                }
                if (wasmBinary) {
                    return await initSqlJs({ wasmBinary });
                }
                return await initSqlJs();
            } catch (e) {
                return await initSqlJs();
            }
        })();
    }
    return SQL_PROMISE;
}

function xorBuffers(a, b) {
    const len = Math.min(a.length, b.length);
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
    return out;
}

function aeadDecrypt(algo, key, iv, ct, tag) {
    try {
        const decipher = crypto.createDecipheriv(
            algo,
            key,
            iv,
            algo === 'chacha20-poly1305' ? { authTagLength: 16 } : undefined
        );
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch {
        return null;
    }
}

function unwrapAppBoundBlob(blob, cngKeyBuf = null) {
    if (!blob || blob.length < 8) return null;

    let keyBlob = blob;
    const valLen = blob.readUInt32LE(0);
    if (valLen < 4096 && 4 + valLen + 4 <= blob.length) {
        const pos = 4 + valLen;
        const blobLen = blob.readUInt32LE(pos);
        if (blobLen > 0 && pos + 4 + blobLen <= blob.length) {
            keyBlob = blob.subarray(pos + 4, pos + 4 + blobLen);
        }
    }

    if (keyBlob.length === 32) return keyBlob;
    if (keyBlob.length < 61) return null;

    const flag = keyBlob[0];
    const body = keyBlob.subarray(1);

    if (flag === 1 && body.length >= 60) {
        const iv = body.subarray(0, 12);
        const ct = body.subarray(12, 44);
        const tag = body.subarray(44, 60);
        return aeadDecrypt('aes-256-gcm', KEY_FLAG1_AES, iv, ct, tag);
    }

    if (flag === 2 && body.length >= 60) {
        const iv = body.subarray(0, 12);
        const ct = body.subarray(12, 44);
        const tag = body.subarray(44, 60);
        return aeadDecrypt('chacha20-poly1305', KEY_FLAG2_CHACHA, iv, ct, tag);
    }

    if (flag === 3 && body.length >= 92) {
        const encK = body.subarray(0, 32);
        const iv = body.subarray(32, 44);
        const ct = body.subarray(44, 76);
        const tag = body.subarray(76, 92);

        const baseCandidates = [cngKeyBuf, encK].filter((b) => b && b.length === 32);
        for (const base of baseCandidates) {
            const kCandidates = [
                xorBuffers(base, KEY_FLAG3_XOR),
                xorBuffers(base, KEY_FLAG2_CHACHA),
                xorBuffers(base, KEY_FLAG1_AES),
                base,
            ];
            for (const kCand of kCandidates) {
                const decAes = aeadDecrypt('aes-256-gcm', kCand, iv, ct, tag);
                if (decAes) return decAes;
                const decCha = aeadDecrypt('chacha20-poly1305', kCand, iv, ct, tag);
                if (decCha) return decCha;
            }
        }
    }

    return null;
}

function parseKeyCandidates(rawInput, cngRawHex = '') {
    const out = [];
    const cngBuf =
        cngRawHex && /^[0-9a-fA-F]{64}$/.test(cngRawHex.trim())
            ? Buffer.from(cngRawHex.trim(), 'hex')
            : null;

    if (rawInput && typeof rawInput === 'string') {
        const clean = rawInput.trim();
        if (/^[0-9a-fA-F]{64}$/.test(clean)) { const raw32 = Buffer.from(clean, 'hex'); out.push(raw32); out.push(xorBuffers(raw32, KEY_FLAG3_XOR)); out.push(xorBuffers(raw32, KEY_FLAG2_CHACHA)); out.push(xorBuffers(raw32, KEY_FLAG1_AES)); } else if (/^[0-9a-fA-F]{122,}$/.test(clean)) {
            const buf = Buffer.from(clean, 'hex');
            const unwrapped = unwrapAppBoundBlob(buf, cngBuf);
            if (unwrapped) out.push(unwrapped);
        } else {
            try {
                const buf = Buffer.from(clean, 'base64');
                if (buf.length === 32) {
                    out.push(buf);
                    out.push(xorBuffers(buf, KEY_FLAG3_XOR));
                } else {
                    const unwrapped = unwrapAppBoundBlob(buf, cngBuf);
                    if (unwrapped) out.push(unwrapped);
                }
            } catch {}
        }
    }
    return out;
}

function stripV20DomainHashPrefix(plaintext) {
    if (plaintext.length > 32) {
        let nonAsciiHead = 0;
        for (let i = 0; i < 32; i++) {
            const b = plaintext[i];
            if (b < 0x20 || b > 0x7e) nonAsciiHead++;
        }
        if (nonAsciiHead >= 4) {
            return plaintext.subarray(32).toString('utf8');
        }
    }
    return plaintext.toString('utf8');
}

function decryptPasswordBlob(blob, candidateKeys) {
    if (!blob || blob.length === 0) return '[EMPTY]';
    const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
    const prefix = buf.subarray(0, 3).toString('ascii');

    if (prefix !== 'v10' && prefix !== 'v11' && prefix !== 'v20') {
        return `[DPAPI_RAW_HEX:${buf.toString('hex')}]`;
    }
    if (buf.length < 31) return `[SHORT_BLOB_${buf.length}B]`;

    const iv = buf.subarray(3, 15);
    const ct = buf.subarray(15, buf.length - 16);
    const tag = buf.subarray(buf.length - 16);

    const allKeys = [
        ...candidateKeys,
        KEY_FLAG1_AES,
        KEY_FLAG2_CHACHA,
        KEY_FLAG3_XOR,
    ];

    for (const k of allKeys) {
        if (!k || k.length !== 32) continue;
        const ptAes = aeadDecrypt('aes-256-gcm', k, iv, ct, tag);
        if (ptAes) {
            return {
                ok: true,
                text: prefix === 'v20' ? stripV20DomainHashPrefix(ptAes) : ptAes.toString('utf8'),
            };
        }
        const ptCha = aeadDecrypt('chacha20-poly1305', k, iv, ct, tag);
        if (ptCha) {
            return {
                ok: true,
                text: prefix === 'v20' ? stripV20DomainHashPrefix(ptCha) : ptCha.toString('utf8'),
            };
        }
    }

    const reason =
        candidateKeys.length === 0
            ? 'MISSING_V20_MASTER_KEY'
            : 'KEY_MISMATCH';

    return {
        ok: false,
        text: `[DECRYPT_FAIL: ${reason} | ver=${prefix}]`,
    };
}

async function parseLoginDataBuffer(sqliteBuffer, candidateKeys) {
    const SQL = await getSqlEngine();
    const db = new SQL.Database(new Uint8Array(sqliteBuffer));
    const records = [];
    let decryptedCount = 0;

    try {
        const res = db.exec(`
            SELECT origin_url, action_url, username_value, password_value,
                   signon_realm, date_created, times_used
            FROM logins
            ORDER BY date_created DESC
        `);
        if (res.length > 0) {
            const rows = res[0].values;
            for (const row of rows) {
                const [origin_url, action_url, username_value, pass_blob, signon_realm, date_created, times_used] = row;
                const rawBytes = pass_blob ? Buffer.from(pass_blob) : Buffer.alloc(0);
                const ver = rawBytes.length >= 3 ? rawBytes.subarray(0, 3).toString('ascii') : 'raw';
                const decResult = decryptPasswordBlob(rawBytes, candidateKeys);
                const plainText = typeof decResult === 'object' ? decResult.text : decResult;
                if (typeof decResult === 'object' && decResult.ok) decryptedCount++;

                if (!username_value && plainText === '[EMPTY]') continue;

                records.push({
                    origin_url: origin_url || '',
                    action_url: action_url || '',
                    signon_realm: signon_realm || '',
                    username_value: username_value || '',
                    password_plaintext: plainText,
                    decrypted_ok: typeof decResult === 'object' ? decResult.ok : false,
                    encryption_version: ver,
                    times_used: times_used || 0,
                    date_created: date_created || 0,
                });
            }
        }
    } finally {
        db.close();
    }
    return { records, decryptedCount };
}

function formatTxtOutput(records) {
    return (
        records
            .map(
                (r, idx) =>
                    `[${String(idx + 1).padStart(3, '0')}] URL: ${r.origin_url} | USER: ${r.username_value} | PASS: ${r.password_plaintext} | VER: ${r.encryption_version}`
            )
            .join('\n') + '\n'
    );
}

function csvEscape(value) {
    const text = String(value ?? '');
    return /[",\n\r]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

function formatCsvOutput(records) {
    const header = 'origin_url,username,password,encryption_version,times_used';
    const rows = records.map((r) =>
        [r.origin_url, r.username_value, r.password_plaintext, r.encryption_version, r.times_used]
            .map(csvEscape)
            .join(',')
    );
    return header + '\n' + rows.join('\n') + '\n';
}

const WEB_UI_HTML = `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chromium Login Data Extractor — Chrome / Edge / Brave / Opera</title>
<style>
  :root { --bg:#0b0f17; --card:#151b26; --border:#2a3447; --accent:#3b82f6; --text:#e2e8f0; --muted:#94a3b8; }
  body { background:var(--bg); color:var(--text); font-family:ui-monospace,SFMono-Regular,Consolas,monospace; margin:0; padding:24px; }
  .container { max-width:1200px; margin:0 auto; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:22px; margin-bottom:20px; }
  h1, h2 { margin-top:0; color:#60a5fa; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  .field { margin-bottom:14px; }
  label { display:block; font-size:13px; color:var(--muted); margin-bottom:6px; font-weight:600; }
  input { width:100%; padding:10px; background:#0b0f17; border:1px solid var(--border); color:var(--text); border-radius:6px; box-sizing:border-box; font-family:inherit; }
  .btns { display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; }
  button { background:var(--accent); color:#fff; border:none; padding:10px 18px; border-radius:6px; cursor:pointer; font-weight:700; font-family:inherit; }
  button.secondary { background:#10b981; }
  button:hover { opacity:0.92; }
  pre { background:#080b11; border:1px solid var(--border); padding:12px; border-radius:6px; overflow-x:auto; font-size:12px; color:#a5b4fc; }
  table { width:100%; border-collapse:collapse; margin-top:16px; font-size:12.5px; }
  th, td { border:1px solid var(--border); padding:8px 10px; text-align:left; word-break:break-all; }
  th { background:#1e293b; color:#93c5fd; }
  .badge { padding:2px 6px; border-radius:4px; background:#1e3a8a; color:#bfdbfe; font-size:11px; }
  .pass-ok { color:#34d399; font-weight:bold; }
  .pass-err { color:#f87171; font-size:11.5px; }
  .warn-box { background:#1e1b4b; border:1px solid #4338ca; padding:12px; border-radius:6px; margin-bottom:16px; font-size:12.5px; color:#c7d2fe; }
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <h1>GIAI MA LOGIN DATA — CHROME / EDGE / BRAVE / OPERA (v2.0.0)</h1>
    <div class="warn-box">
      <strong>Hướng dẫn:</strong> Chọn file <code>Login Data</code> của Chrome / Edge / Brave / Opera / Vivaldi (cùng định dạng SQLite) và nhập <code>v20 Master Key (64 ký tự hex)</code> lấy từ file <code>Local State</code> để giải mã mật khẩu. API key là giá trị <code>EXTRACTOR_API_KEY</code> đã set trên Vercel.
    </div>
    <form id="extractForm">
      <div class="grid">
        <div class="field">
          <label>API Key (Header: x-api-key) *</label>
          <input type="password" id="apiKey" placeholder="EXTRACTOR_API_KEY đã set trên Vercel" required />
        </div>
        <div class="field">
          <label>File "Login Data" (SQLite) *</label>
          <input type="file" id="loginFile" required />
        </div>
        <div class="field">
          <label>v20 Master Key (64 ký tự hex)</label>
          <input type="text" id="v20Key" placeholder="64 ky tu hex v20 Key" />
        </div>
        <div class="field">
          <label>v10 Master Key (64 ký tự hex)</label>
          <input type="text" id="v10Key" placeholder="64 ky tu hex v10 Key" />
        </div>
      </div>
      <div class="btns">
        <button type="submit">1. Giải Mã & Xem Trực Tiếp</button>
        <button type="button" class="secondary" id="btnDownloadTxt">2. Gửi API & Tải File .TXT</button>
        <button type="button" class="secondary" id="btnDownloadJson">3. Gửi API & Tải File .JSON</button>
        <button type="button" class="secondary" id="btnDownloadCsv">4. Gửi API & Tải File .CSV</button>
      </div>
    </form>
    <div id="status" style="margin-top:14px;color:#94a3b8;font-size:13px;"></div>
    <div id="tableWrap"></div>
  </div>
</div>

<script>
const escHtml = (str) => String(str ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

const fileToB64 = (file) => new Promise((res, rej) => {
  const r = new FileReader();
  r.onload = () => res(r.result.split(',')[1]);
  r.onerror = rej;
  r.readAsDataURL(file);
});

async function callApi(outputFormat) {
  const apiKey = document.getElementById('apiKey').value.trim();
  const fileInput = document.getElementById('loginFile').files[0];
  const v20Key = document.getElementById('v20Key').value.trim();
  const v10Key = document.getElementById('v10Key').value.trim();
  const statusEl = document.getElementById('status');
  const tableWrap = document.getElementById('tableWrap');

  if (!apiKey || !fileInput) {
    statusEl.textContent = '[!] Vui lòng nhập API Key và chọn file Login Data.';
    return;
  }

  statusEl.textContent = 'Đang gửi file Login Data lên API endpoint...';
  const loginB64 = await fileToB64(fileInput);

  const resp = await fetch('/api/extract?output=' + encodeURIComponent(outputFormat), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey
    },
    body: JSON.stringify({
      login_data_b64: loginB64,
      v20_key: v20Key,
      v10_key: v10Key,
      output: outputFormat
    })
  });

  if (!resp.ok) {
    const errText = await resp.text();
    statusEl.textContent = '[!] Loi API (' + resp.status + '): ' + errText;
    return;
  }

  if (outputFormat === 'txt_file' || outputFormat === 'json_file' || outputFormat === 'csv_file') {
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = outputFormat === 'txt_file' ? 'decrypted_accounts.txt' : (outputFormat === 'csv_file' ? 'decrypted_logins.csv' : 'decrypted_logins.json');
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    statusEl.textContent = '[+] Đã nhận và tải file trích xuất từ API thành công!';
    return;
  }

  const data = await resp.json();
  statusEl.textContent = '[+] Tổng: ' + data.total + ' tài khoản | Giải mã thành công: ' + data.decrypted_count + '/' + data.total;
  let html = '<table><thead><tr><th>#</th><th>Origin URL</th><th>Username</th><th>Password</th><th>Ver</th></tr></thead><tbody>';
  data.records.forEach((r, i) => {
    const passClass = r.decrypted_ok ? 'pass-ok' : 'pass-err';
    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td>' + escHtml(r.origin_url) + '</td>' +
      '<td>' + escHtml(r.username_value) + '</td>' +
      '<td class="' + passClass + '">' + escHtml(r.password_plaintext) + '</td>' +
      '<td><span class="badge">' + escHtml(r.encryption_version) + '</span></td>' +
    '</tr>';
  });
  html += '</tbody></table>';
  tableWrap.innerHTML = html;
}

document.getElementById('extractForm').addEventListener('submit', (e) => {
  e.preventDefault();
  callApi('json');
});
document.getElementById('btnDownloadTxt').addEventListener('click', () => callApi('txt_file'));
document.getElementById('btnDownloadJson').addEventListener('click', () => callApi('json_file'));
document.getElementById('btnDownloadCsv').addEventListener('click', () => callApi('csv_file'));
</script>
</body>
</html>`;

function readRequestBuffer(req, maxBytes) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0;
        req.on('data', (c) => {
            const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
            total += buf.length;
            if (total > maxBytes) {
                reject(new Error('PAYLOAD_TOO_LARGE'));
                req.destroy();
                return;
            }
            chunks.push(buf);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

async function handler(req, res) {
    // CORS: only this site's own origin may call the API from a browser
    const reqOrigin = req.headers.origin;
    if (reqOrigin) {
        try {
            if (new URL(reqOrigin).host === req.headers.host) {
                res.setHeader('Access-Control-Allow-Origin', reqOrigin);
                res.setHeader('Vary', 'Origin');
            }
        } catch {}
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key, x-v10-key, x-v20-key');

    if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        return res.end();
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'GET' && (parsedUrl.pathname === '/' || parsedUrl.pathname === '/api')) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(WEB_UI_HTML);
    }

    if (req.method === 'POST' && parsedUrl.pathname.startsWith('/api/extract')) {
        if (!API_KEY) {
            res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(JSON.stringify({ ok: false, error: 'Server is not configured: EXTRACTOR_API_KEY is missing' }));
        }

        const clientIp = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || 'unknown';
        if (isRateLimited(clientIp)) {
            res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(JSON.stringify({ ok: false, error: 'Too many requests — try again in a minute' }));
        }

        const clientKey =
            req.headers['x-api-key'] ||
            parsedUrl.searchParams.get('api_key') ||
            parsedUrl.searchParams.get('apikey');

        if (!keyMatches(clientKey)) {
            res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(JSON.stringify({ ok: false, error: 'Invalid or missing x-api-key' }));
        }

        try {
            const rawBody = await readRequestBuffer(req, MAX_BODY_BYTES);
            const contentType = (req.headers['content-type'] || '').toLowerCase();

            let sqliteBuffer = null;
            let v20Raw = req.headers['x-v20-key'] || parsedUrl.searchParams.get('v20_key') || '';
            let v10Raw = req.headers['x-v10-key'] || parsedUrl.searchParams.get('v10_key') || '';
            let outputMode = parsedUrl.searchParams.get('output') || 'json';

            if (contentType.includes('application/json')) {
                const bodyJson = JSON.parse(rawBody.toString('utf8'));
                if (!bodyJson.login_data_b64) {
                    throw new Error('Missing login_data_b64 in JSON payload');
                }
                sqliteBuffer = Buffer.from(bodyJson.login_data_b64, 'base64');
                v20Raw = bodyJson.v20_key || v20Raw;
                v10Raw = bodyJson.v10_key || v10Raw;
                outputMode = bodyJson.output || outputMode;
            } else {
                sqliteBuffer = rawBody;
            }

            if (!sqliteBuffer || sqliteBuffer.length < 100) {
                throw new Error('Invalid or empty SQLite Login Data file');
            }
            if (sqliteBuffer.length > MAX_SQLITE_BYTES) {
                throw new Error('PAYLOAD_TOO_LARGE');
            }
            if (sqliteBuffer.subarray(0, 15).toString('latin1') !== 'SQLite format 3') {
                throw new Error('Uploaded file is not a valid SQLite Login Data file');
            }

            const candidateKeys = [
                ...parseKeyCandidates(v20Raw),
                ...parseKeyCandidates(v10Raw),
            ];

            const { records, decryptedCount } = await parseLoginDataBuffer(sqliteBuffer, candidateKeys);

            if (outputMode === 'txt' || outputMode === 'txt_file' || outputMode === 'file') {
                const txtPayload = formatTxtOutput(records);
                res.writeHead(200, {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Content-Disposition': 'attachment; filename="decrypted_accounts.txt"',
                });
                return res.end(txtPayload);
            }

            if (outputMode === 'csv' || outputMode === 'csv_file') {
                const csvPayload = formatCsvOutput(records);
                res.writeHead(200, {
                    'Content-Type': 'text/csv; charset=utf-8',
                    'Content-Disposition': 'attachment; filename="decrypted_logins.csv"',
                });
                return res.end(csvPayload);
            }

            if (outputMode === 'json_file') {
                const jsonPayload = JSON.stringify(records, null, 2);
                res.writeHead(200, {
                    'Content-Type': 'application/json; charset=utf-8',
                    'Content-Disposition': 'attachment; filename="decrypted_logins.json"',
                });
                return res.end(jsonPayload);
            }

            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(
                JSON.stringify({
                    ok: true,
                    total: records.length,
                    decrypted_count: decryptedCount,
                    keys_loaded: candidateKeys.length,
                    records,
                    txt_content: formatTxtOutput(records),
                })
            );
        } catch (err) {
            if (err && err.message === 'PAYLOAD_TOO_LARGE') {
                res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' });
                return res.end(JSON.stringify({ ok: false, error: 'Uploaded file is too large (max 25MB Login Data / 32MB request body)' }));
            }
            const knownErrors = [
                'Missing login_data_b64 in JSON payload',
                'Invalid or empty SQLite Login Data file',
                'Uploaded file is not a valid SQLite Login Data file',
            ];
            const message = knownErrors.includes(err && err.message)
                ? err.message
                : 'Could not process the Login Data file (corrupt or unsupported format)';
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(JSON.stringify({ ok: false, error: message }));
        }
    }

    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: false, error: 'Route not found' }));
}

module.exports = handler;

if (require.main === module) {
    const port = process.env.PORT || 3000;
    http.createServer(handler).listen(port, () => {
        console.log(`[+] Server running at http://127.0.0.1:${port}`);
    });
}
