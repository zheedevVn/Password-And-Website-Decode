<div align="center">

# 🔓 Password-And-Website-Decode

### Giải mã file `Login Data` của Chrome — trích xuất mật khẩu đã lưu (DPAPI + App-Bound v127+)

[![Vercel](https://img.shields.io/badge/Vercel-Serverless-black?logo=vercel)](https://vercel.com)
[![Node](https://img.shields.io/badge/Node-%3E%3D18-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*Khôi phục mật khẩu đã lưu trên Chrome của chính bạn — chạy serverless, không cần cài đặt gì.*

</div>

---

## ✨ Tính năng

- 📂 Đọc trực tiếp file `Login Data` (SQLite) của Chrome bằng `sql.js` — không cần Chrome đang chạy
- 🔑 Giải mã **App-Bound Encryption** (Chrome v127+): AES-256-GCM / ChaCha20-Poly1305 / XOR, kèm fallback DPAPI v10
- 🌐 Chạy **serverless trên Vercel** — upload file qua web UI hoặc API, nhận kết quả ngay
- 🖥️ Kèm **Web UI** gọn nhẹ: kéo-thả file, xem/tải kết quả JSON hoặc TXT
- 🔐 Bảo vệ bằng API key (`x-api-key` header hoặc `?api_key=`)

## 🚀 Deploy 1-click

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/zheedevVn/Password-And-Website-Decode)

Nhớ set biến môi trường `EXTRACTOR_API_KEY` trên Vercel (Settings → Environment Variables) — key mặc định trong code chỉ để dev local.

Chạy local:

```bash
npm install
npm start   # http://127.0.0.1:3000
```

## 📖 Cách dùng

**Web UI:** mở `/` trên trình duyệt → upload file `Login Data` → dán key giải mã (lấy từ file `Local State` của Chrome) → nhận kết quả.

File cần thiết (trên máy của bạn):
| File | Đường dẫn Chrome (Windows) |
|---|---|
| `Login Data` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\` |
| `Local State` (lấy key) | `%LOCALAPPDATA%\Google\Chrome\User Data\` |

> ⚠️ Copy file ra chỗ khác trước khi upload — Chrome đang chạy sẽ khóa file gốc.

**API:**

```bash
# Upload file Login Data (raw binary)
curl -X POST "https://your-app.vercel.app/api/extract?output=json" \
  -H "x-api-key: YOUR_KEY" \
  -H "x-v20-key: <app-bound-key>" \
  -H "x-v10-key: <dpapi-key>" \
  --data-binary "@Login Data"

# Hoặc gửi JSON base64
curl -X POST "https://your-app.vercel.app/api/extract" \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_KEY" \
  -d '{"login_data_b64":"...","v20_key":"...","v10_key":"...","output":"json"}'
```

Tham số `output`: `json` (mặc định) · `json_file` · `txt` / `txt_file` (tải file `.txt`)

Response mẫu:

```json
{
  "ok": true,
  "total": 42,
  "decrypted_count": 40,
  "records": [
    { "origin_url": "https://example.com", "username": "user@example.com", "password": "••••••" }
  ]
}
```

## ⚠️ Lưu ý bảo mật

- Tool này chỉ dùng để **khôi phục mật khẩu của chính bạn** trên máy của bạn.
- **Đừng bao giờ** upload file `Login Data` lên server lạ — ai có file đó + key đều đọc được toàn bộ mật khẩu của bạn.
- Đổi `EXTRACTOR_API_KEY` mặc định ngay sau khi deploy.

## 📄 Giấy phép

[MIT](LICENSE) — © 2026 Ho Duc Minh
