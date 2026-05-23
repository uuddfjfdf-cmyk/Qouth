// ═══════════════════════════════════════════════
//  AuthLab — Backend Server
//  Node.js + Express + MongoDB + JWT
// ═══════════════════════════════════════════════

// ── LOAD ENV (HARUS PALING ATAS, SEBELUM APAPUN) ─
require('dotenv').config();

// ── DEBUG: CEK ENV VARS SAAT STARTUP ────────────
console.log('🔍 ENV Check:');
console.log('   NODE_ENV   :', process.env.NODE_ENV   || '(tidak di-set)');
console.log('   PORT       :', process.env.PORT       || '(tidak di-set, default 3000)');
console.log('   MONGO_URI  :', process.env.MONGO_URI  ? '✅ terbaca' : '❌ TIDAK TERBACA');
console.log('   JWT_SECRET :', process.env.JWT_SECRET ? '✅ terbaca' : '❌ TIDAK TERBACA');
console.log('   FRONTEND_URL:', process.env.FRONTEND_URL || '(tidak di-set)');

// ── VALIDASI ENV WAJIB (FAIL FAST) ──────────────
const REQUIRED_ENV = ['MONGO_URI', 'JWT_SECRET', 'JWT_REFRESH_SECRET'];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);

if (missingEnv.length > 0) {
  console.error('\n❌ Environment variable berikut belum di-set:');
  missingEnv.forEach((key) => console.error(`   - ${key}`));
  console.error('\n💡 Solusi:');
  console.error('   • Lokal  : pastikan file .env ada dan berisi variable di atas');
  console.error('   • Railway: buka Settings → Variables → tambahkan variable tersebut');
  console.error('   • Pastikan nama variable PERSIS sama (case-sensitive)\n');
  process.exit(1);
}

const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ──────────────────────────────────
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5500',
  credentials: true,
}));

// ── RATE LIMITER (brute force protection) ───────
const loginLimiter = rateLimit({
  windowMs : 15 * 60 * 1000, // 15 menit
  max      : 5,               // max 5 percobaan
  message  : { success: false, message: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' },
  standardHeaders: true,
  legacyHeaders  : false,
});

// ── MONGODB CONNECTION ──────────────────────────
console.log('\n🔌 Menghubungkan ke MongoDB...');

mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS : 30000, // timeout 30 detik
  socketTimeoutMS          : 45000,
  family                   : 4,     // paksa IPv4 (fix masalah koneksi di Railway/cloud)
})
  .then(() => {
    console.log('✅ MongoDB terhubung:', mongoose.connection.host);
  })
  .catch((err) => {
    console.error('❌ MongoDB gagal konek:', err.message);
    console.error('\n💡 Kemungkinan penyebab:');
    console.error('   • MONGO_URI salah format (harus: mongodb+srv://user:pass@host/db)');
    console.error('   • IP server belum di-whitelist di MongoDB Atlas (gunakan 0.0.0.0/0 untuk Railway)');
    console.error('   • Username/password salah');
    console.error('   • Cluster Atlas sedang mati\n');
    process.exit(1);
  });

// ── MONGOOSE EVENT LISTENERS ────────────────────
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️  MongoDB terputus. Mencoba reconnect...');
});
mongoose.connection.on('reconnected', () => {
  console.log('🔄 MongoDB berhasil reconnect');
});

// ── SCHEMA & MODEL ─────────────────────────────
const userSchema = new mongoose.Schema({
  firstName : { type: String, trim: true },
  lastName  : { type: String, trim: true },
  username  : { type: String, unique: true, lowercase: true, trim: true },
  email     : { type: String, required: true, unique: true, lowercase: true, trim: true },
  password  : { type: String },          // null jika OAuth
  provider  : { type: String, default: 'local' }, // local | google | github
  isVerified: { type: Boolean, default: false },
  createdAt : { type: Date, default: Date.now },
});

// Jangan return field sensitif secara default
userSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.__v;
  return obj;
};

const User = mongoose.model('User', userSchema);

// OTP / Magic Link store (simpel pakai MongoDB)
const tokenSchema = new mongoose.Schema({
  email     : String,
  token     : String,
  type      : String,       // 'otp' | 'magic'
  expiresAt : Date,
  used      : { type: Boolean, default: false },
});
const TokenRecord = mongoose.model('TokenRecord', tokenSchema);

// ── HELPERS ─────────────────────────────────────
const signAccessToken = (userId) =>
  jwt.sign({ uid: userId }, process.env.JWT_SECRET, { expiresIn: '15m' });

const signRefreshToken = (userId) =>
  jwt.sign({ uid: userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

const respond = (res, status, success, message, data = {}) =>
  res.status(status).json({ success, message, ...data });

// ── MIDDLEWARE: AUTH GUARD ──────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return respond(res, 401, false, 'Token tidak ditemukan');
  try {
    req.user = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch (err) {
    return respond(res, 401, false, 'Token tidak valid atau sudah expired');
  }
}

// ════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════

// ── HEALTH CHECK ────────────────────────────────
app.get('/api/health', (req, res) => {
  respond(res, 200, true, 'Server berjalan normal', {
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

// ── REGISTER ────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, username, email, password } = req.body;

    // Validasi input
    if (!email || !password)
      return respond(res, 400, false, 'Email dan password wajib diisi');
    if (password.length < 8)
      return respond(res, 400, false, 'Password minimal 8 karakter');

    // Cek duplikat
    const existingEmail = await User.findOne({ email });
    if (existingEmail)
      return respond(res, 409, false, 'Email sudah terdaftar');

    if (username) {
      const existingUsername = await User.findOne({ username });
      if (existingUsername)
        return respond(res, 409, false, 'Username sudah dipakai');
    }

    // Hash password
    const hash = await bcrypt.hash(password, 12);

    // Simpan user
    const user = await User.create({
      firstName, lastName, username, email,
      password: hash,
      provider : 'local',
    });

    // Generate token
    const accessToken  = signAccessToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    respond(res, 201, true, 'Akun berhasil dibuat', {
      user        : user.toSafeJSON(),
      accessToken,
      refreshToken,
    });

  } catch (err) {
    console.error('Register error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── LOGIN ────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return respond(res, 400, false, 'Email dan password wajib diisi');

    // Cari user (bisa pakai email atau username)
    const user = await User.findOne({
      $or: [{ email }, { username: email }],
    });

    if (!user || !user.password)
      return respond(res, 401, false, 'Email atau password salah');

    // Bandingkan password dengan hash
    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return respond(res, 401, false, 'Email atau password salah');

    // Generate token
    const accessToken  = signAccessToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    respond(res, 200, true, 'Login berhasil', {
      user        : user.toSafeJSON(),
      accessToken,
      refreshToken,
    });

  } catch (err) {
    console.error('Login error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── REFRESH TOKEN ────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return respond(res, 400, false, 'Refresh token diperlukan');

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user    = await User.findById(decoded.uid);

    if (!user)
      return respond(res, 404, false, 'User tidak ditemukan');

    const newAccessToken = signAccessToken(user._id);
    respond(res, 200, true, 'Token diperbarui', { accessToken: newAccessToken });

  } catch (err) {
    respond(res, 401, false, 'Refresh token tidak valid atau expired');
  }
});

// ── CHECK USERNAME AVAILABILITY ─────────────────
app.get('/api/auth/check-username', async (req, res) => {
  try {
    const { username } = req.query;
    if (!username || username.length < 3)
      return respond(res, 400, false, 'Username terlalu pendek');

    const exists = await User.findOne({ username: username.toLowerCase() });
    respond(res, 200, true, exists ? 'Username sudah dipakai' : 'Username tersedia', {
      available: !exists,
    });
  } catch (err) {
    respond(res, 500, false, 'Internal server error');
  }
});

// ── SEND MAGIC LINK ──────────────────────────────
app.post('/api/auth/magic-link', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return respond(res, 400, false, 'Email diperlukan');

    const token     = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 menit

    // Hapus token lama untuk email ini
    await TokenRecord.deleteMany({ email, type: 'magic' });

    // Simpan token baru
    await TokenRecord.create({ email, token, type: 'magic', expiresAt });

    const link = `${process.env.FRONTEND_URL}/verify?token=${token}`;

    // ─ Kirim email (gunakan Nodemailer/Resend/SendGrid) ─
    // Contoh dengan Nodemailer (uncomment kalau sudah setup):
    //
    // const transporter = nodemailer.createTransport({ ...smtpConfig });
    // await transporter.sendMail({
    //   from   : '"AuthLab" <noreply@authlab.io>',
    //   to     : email,
    //   subject: 'Login ke AuthLab',
    //   html   : `<a href="${link}">Klik untuk masuk</a> (berlaku 15 menit)`,
    // });

    console.log(`[DEV] Magic link untuk ${email}: ${link}`);
    respond(res, 200, true, 'Magic link berhasil dikirim (cek terminal di dev mode)');

  } catch (err) {
    console.error('Magic link error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── VERIFY MAGIC LINK ────────────────────────────
app.get('/api/auth/verify-magic', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return respond(res, 400, false, 'Token diperlukan');

    const record = await TokenRecord.findOne({ token, type: 'magic', used: false });

    if (!record)
      return respond(res, 400, false, 'Token tidak valid');
    if (new Date() > record.expiresAt)
      return respond(res, 400, false, 'Token sudah expired');

    // Tandai token sebagai sudah dipakai (one-use)
    record.used = true;
    await record.save();

    // Cari atau buat user
    let user = await User.findOne({ email: record.email });
    if (!user) {
      user = await User.create({ email: record.email, provider: 'magic', isVerified: true });
    }

    const accessToken  = signAccessToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    respond(res, 200, true, 'Login via magic link berhasil', {
      user: user.toSafeJSON(), accessToken, refreshToken,
    });

  } catch (err) {
    console.error('Verify magic error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── SEND OTP ─────────────────────────────────────
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return respond(res, 400, false, 'Nomor HP diperlukan');

    const otp       = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 menit

    // Hapus OTP lama
    await TokenRecord.deleteMany({ email: phone, type: 'otp' });

    // Simpan OTP baru (hash kalau mau lebih aman)
    await TokenRecord.create({ email: phone, token: otp, type: 'otp', expiresAt });

    // ─ Kirim via SMS (Twilio, Vonage, dll) ─
    // Contoh Twilio (uncomment kalau sudah setup):
    //
    // await twilioClient.messages.create({
    //   body: `Kode OTP AuthLab kamu: ${otp} (berlaku 10 menit)`,
    //   from: process.env.TWILIO_PHONE,
    //   to  : `+62${phone}`,
    // });

    console.log(`[DEV] OTP untuk ${phone}: ${otp}`);
    respond(res, 200, true, 'OTP berhasil dikirim (cek terminal di dev mode)', {
      // HAPUS baris ini di production!
      devOtp: process.env.NODE_ENV === 'development' ? otp : undefined,
    });

  } catch (err) {
    console.error('Send OTP error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── VERIFY OTP ───────────────────────────────────
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp)
      return respond(res, 400, false, 'Nomor HP dan OTP diperlukan');

    const record = await TokenRecord.findOne({ email: phone, type: 'otp', used: false });

    if (!record || record.token !== otp)
      return respond(res, 400, false, 'OTP tidak valid');
    if (new Date() > record.expiresAt)
      return respond(res, 400, false, 'OTP sudah expired');

    record.used = true;
    await record.save();

    respond(res, 200, true, 'OTP berhasil diverifikasi', { verified: true });

  } catch (err) {
    console.error('Verify OTP error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── GET PROFILE (protected) ──────────────────────
app.get('/api/user/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.uid);
    if (!user) return respond(res, 404, false, 'User tidak ditemukan');
    respond(res, 200, true, 'Profil berhasil diambil', { user: user.toSafeJSON() });
  } catch (err) {
    respond(res, 500, false, 'Internal server error');
  }
});

// ── GLOBAL ERROR HANDLER ─────────────────────────
app.use((err, req, res, next) => {
  console.error('🔥 Unhandled error:', err);
  respond(res, 500, false, 'Internal server error');
});

// ── START SERVER ─────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 AuthLab server berjalan di http://localhost:${PORT}`);
  console.log(`📋 Environment : ${process.env.NODE_ENV || 'development'}`);
  console.log(`📋 File aktif  : ${__filename}\n`);
});

// ── GRACEFUL SHUTDOWN ────────────────────────────
process.on('SIGTERM', async () => {
  console.log('⚠️  SIGTERM diterima. Menutup server dengan bersih...');
  await mongoose.connection.close();
  console.log('✅ Koneksi MongoDB ditutup. Server berhenti.');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('💥 Unhandled Rejection:', reason);
  process.exit(1);
});
