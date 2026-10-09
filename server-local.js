// Jalankan lokal: npm install && node server-local.js  (butuh file .env atau env variable)
const express = require('express');
const path = require('path');
const api = require('./api/index.js');
const app = express();
app.use(api);
app.use(express.static(path.join(__dirname, 'public')));
app.listen(3000, () => console.log('http://localhost:3000'));
