# AuthLab — Setup Guide

## Struktur File

```
authlab/
├── backend/
│   ├── server.js          ← Backend Node.js (Express + MongoDB)
│   ├── package.json       ← Dependencies
│   └── .env.example       ← Template environment variables
└── frontend/
    └── index.html         ← Frontend (sudah terhubung ke backend)
```

---

## ⚡ Cara Setup (Step by Step)

### 1. Install MongoDB
- **Windows/Mac**: Download di https://www.mongodb.com/try/download/community
- **Atau pakai MongoDB Atlas** (cloud, gratis): https://www.mongodb.com/atlas

### 2. Setup Backend

```bash
# Masuk ke folder backend
cd authlab/backend

# Install semua dependencies
npm install

# Copy file env
cp .env.example .env

# Edit .env — isi nilai yang diperlukan:
# - MONGO_URI (ganti kalau pakai Atlas)
# - JWT_SECRET (generate random string panjang)
# - JWT_REFRESH_SECRET (generate random string lain)
```

**Generate JWT Secret di terminal:**
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 3. Jalankan Backend

```bash
# Mode development (auto-restart saat ada perubahan)
npm run dev

# Atau mode biasa
npm start
```

Kalau berhasil, terminal tampil:
```
✅ MongoDB terhubung
🚀 AuthLab server berjalan di http://localhost:3000
```

### 4. Jalankan Frontend

Buka `frontend/index.html` di browser.

> Rekomendasi: pakai **Live Server** (VS Code extension) agar jalan di port 5500.
> Atau: `npx serve frontend` lalu buka http://localhost:3000

---

## 🔗 API Endpoints

| Method | Endpoint                    | Deskripsi              | Auth? |
|--------|-----------------------------|------------------------|-------|
| GET    | /api/health                 | Cek status server      | Tidak |
| POST   | /api/auth/register          | Daftar akun baru       | Tidak |
| POST   | /api/auth/login             | Login                  | Tidak |
| POST   | /api/auth/refresh           | Refresh access token   | Tidak |
| GET    | /api/auth/check-username    | Cek username tersedia  | Tidak |
| POST   | /api/auth/magic-link        | Kirim magic link       | Tidak |
| GET    | /api/auth/verify-magic      | Verifikasi magic link  | Tidak |
| POST   | /api/auth/send-otp          | Kirim OTP SMS          | Tidak |
| POST   | /api/auth/verify-otp        | Verifikasi OTP         | Tidak |
| GET    | /api/user/profile           | Ambil profil user      | Ya    |

---

## 🧪 Test API (tanpa frontend)

```bash
# Health check
curl http://localhost:3000/api/health

# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"budi@email.com","password":"Password123!","username":"budi"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"budi@email.com","password":"Password123!"}'

# Get Profile (ganti TOKEN dengan access token dari login)
curl http://localhost:3000/api/user/profile \
  -H "Authorization: Bearer TOKEN"
```

---

## ❌ Troubleshooting Error Umum

### `Failed to fetch` / `ERR_CONNECTION_REFUSED`
- Backend belum jalan → jalankan `npm run dev` di folder backend
- Port salah → cek `API_BASE` di `frontend/index.html` (default: 3000)

### `CORS error`
- `FRONTEND_URL` di `.env` tidak cocok dengan port frontend
- Ubah nilainya ke URL yang benar (misal `http://localhost:5500`)

### `MongoServerError: connect ECONNREFUSED`
- MongoDB tidak berjalan → start MongoDB service
- MONGO_URI salah → cek format di `.env`

### `Error: secretOrPrivateKey must have a value`
- `JWT_SECRET` di `.env` belum diisi → isi dengan string random

### `401 Unauthorized` saat login
- Password salah
- Email tidak terdaftar
- Coba register dulu lalu login

---

## 📦 Dependencies yang Diinstall

| Package             | Fungsi                               |
|---------------------|--------------------------------------|
| express             | Web framework                        |
| mongoose            | ODM untuk MongoDB                    |
| bcryptjs            | Hash & compare password              |
| jsonwebtoken        | Generate & verify JWT                |
| cors                | Allow request dari frontend          |
| dotenv              | Load variabel dari file .env         |
| express-rate-limit  | Proteksi brute force login           |
| nodemon (dev)       | Auto-restart server saat ada perubahan |
