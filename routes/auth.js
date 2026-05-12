const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { pool } = require('../db');

function sign(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Register
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  try {
    // First user ever becomes admin
    const { rows: [{ count }] } = await pool.query('SELECT COUNT(*) FROM users');
    const role = count === '0' ? 'admin' : 'user';

    const hash = await bcrypt.hash(password, 12);
    const { rows: [user] } = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email, role',
      [username.trim(), email.trim().toLowerCase(), hash, role]
    );
    res.json({ token: sign(user), user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username or email already taken' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'All fields required' });

  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $1',
      [username.trim()]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    res.json({
      token: sign(user),
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
