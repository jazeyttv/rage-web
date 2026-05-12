require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const { initDb } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// rage.lua verify endpoint
app.use('/', require('./routes/verify'));

// API
app.use('/api/auth',  require('./routes/auth'));
app.use('/api/user',  require('./routes/user'));
app.use('/api/admin', require('./routes/admin'));

// Page routes
const pages = ['login', 'register', 'dashboard', 'admin'];
pages.forEach(p =>
  app.get(`/${p}`, (_, res) => res.sendFile(path.join(__dirname, 'public', `${p}.html`)))
);
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log(`rage server :${PORT}`)))
  .catch(e => { console.error('DB init failed:', e); process.exit(1); });
