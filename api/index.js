const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json({ limit: '1mb' }));

// Koneksi di-cache agar tidak membuka koneksi baru tiap request (serverless)
let cached;
function getDb() {
  if (!cached) {
    cached = new MongoClient(process.env.MONGODB_URI).connect().then(async (c) => {
      const db = c.db(process.env.DB_NAME || 'plantcheck');
      await db.collection('users').createIndex({ email: 1 }, { unique: true });
      return db;
    });
  }
  return cached;
}

const sign = (u) => jwt.sign({ id: u._id.toString() }, process.env.JWT_SECRET, { expiresIn: '7d' });
const clean = (u) => ({ name: u.name, email: u.email, avatar: u.avatar || '', bio: u.bio || '' });
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  console.error(e);
  cached = null;
  res.status(500).json({ error: 'Server bermasalah. Cek MONGODB_URI dan Network Access di MongoDB Atlas.' });
});

async function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.uid = jwt.verify(t, process.env.JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: 'Sesi berakhir. Silakan masuk lagi.' });
  }
}

app.post('/api/register', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2) return res.status(400).json({ error: 'Nama minimal 2 karakter.' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Format email tidak valid.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter.' });
  const db = await getDb();
  try {
    const r = await db.collection('users').insertOne({ name, email, pass: await bcrypt.hash(password, 10), createdAt: new Date() });
    res.json({ token: sign({ _id: r.insertedId }), user: { name, email, avatar: '', bio: '' } });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Email sudah terdaftar. Coba masuk.' });
    throw e;
  }
}));

app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const db = await getDb();
  const u = await db.collection('users').findOne({ email });
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.pass)))
    return res.status(401).json({ error: 'Email atau password salah.' });
  res.json({ token: sign(u), user: clean(u) });
}));

app.post('/api/forgot', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const db = await getDb();
  const u = await db.collection('users').findOne({ email });
  const out = { message: 'Jika email terdaftar, kode reset sudah dikirim. Berlaku 15 menit.' };
  if (u) {
    const code = String(crypto.randomInt(100000, 1000000));
    await db.collection('users').updateOne({ _id: u._id }, { $set: { reset: { h: hash(code), exp: Date.now() + 15 * 60 * 1000 } } });
    if (process.env.SMTP_HOST) {
      const t = nodemailer.createTransport({
        host: process.env.SMTP_HOST, port: +(process.env.SMTP_PORT || 465), secure: +(process.env.SMTP_PORT || 465) === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      });
      await t.sendMail({ from: process.env.SMTP_USER, to: email, subject: 'Kode reset password',
        text: `Kode reset password Anda: ${code}\nBerlaku 15 menit. Abaikan email ini jika Anda tidak memintanya.` });
    }
    if (process.env.DEMO_RESET === 'true') out.demoCode = code;
  }
  res.json(out);
}));

app.post('/api/reset', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  const password = String(req.body.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'Password baru minimal 6 karakter.' });
  const db = await getDb();
  const u = await db.collection('users').findOne({ email });
  if (!u || !u.reset || u.reset.exp < Date.now() || u.reset.h !== hash(code))
    return res.status(400).json({ error: 'Kode salah atau sudah kedaluwarsa.' });
  await db.collection('users').updateOne({ _id: u._id }, { $set: { pass: await bcrypt.hash(password, 10) }, $unset: { reset: '' } });
  res.json({ message: 'Password berhasil diubah. Silakan masuk.' });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const { ObjectId } = require('mongodb');
  const u = await (await getDb()).collection('users').findOne({ _id: new ObjectId(req.uid) });
  if (!u) return res.status(401).json({ error: 'Akun tidak ditemukan.' });
  res.json({ user: clean(u) });
}));

app.put('/api/profile', auth, wrap(async (req, res) => {
  const { ObjectId } = require('mongodb');
  const set = {};
  if (typeof req.body.name === 'string' && req.body.name.trim().length >= 2) set.name = req.body.name.trim();
  if (typeof req.body.bio === 'string') set.bio = req.body.bio.slice(0, 160);
  if (typeof req.body.avatar === 'string' && req.body.avatar.startsWith('data:image/') && req.body.avatar.length < 300000) set.avatar = req.body.avatar;
  const db = await getDb();
  await db.collection('users').updateOne({ _id: new ObjectId(req.uid) }, { $set: set });
  const u = await db.collection('users').findOne({ _id: new ObjectId(req.uid) });
  res.json({ user: clean(u) });
}));

module.exports = app;
