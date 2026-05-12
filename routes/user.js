const router   = require('express').Router();
const { pool } = require('../db');
const { auth } = require('../middleware/auth');

// Current user info
router.get('/me', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, email, role, created_at FROM users WHERE id = $1',
    [req.user.id]
  );
  res.json(rows[0] || null);
});

// User's assigned keys
router.get('/keys', auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, key_code, product, expires_at, active, hwid IS NOT NULL AS hwid_bound, created_at
     FROM license_keys
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [req.user.id]
  );
  res.json(rows);
});

module.exports = router;
