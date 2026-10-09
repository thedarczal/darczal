# Simple Plant Disease Checker (PKM-KC Kelompok 12)

## Struktur
- public/index.html  -> seluruh frontend
- api/index.js       -> backend Express (serverless di Vercel)
- vercel.json        -> routing /api/*

## Jalankan lokal
1. npm install
2. salin .env.example menjadi .env, isi MONGODB_URI dan JWT_SECRET
3. (Mac/Linux) export $(cat .env | xargs) && npm run dev  -> http://localhost:3000

## Deploy ke Vercel
Lihat penjelasan di chat. Environment variable wajib: MONGODB_URI, JWT_SECRET.
"# darczal" 
"# darczal" 
