const router     = require('express').Router();
const { pool }   = require('../db');
const { adminOnly } = require('../middleware/auth');

function genKeyCode() {
  const seg = () => Math.random().toString(36).slice(2, 6).toUpperCase();
  return `RAGE-${seg()}-${seg()}-${seg()}`;
}

// ── Users ─────────────────────────────────────────────────────────────────────

router.get('/users', adminOnly, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.id, u.username, u.email, u.role, u.created_at,
           COUNT(k.id) AS key_count
    FROM users u
    LEFT JOIN license_keys k ON k.user_id = u.id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `);
  res.json(rows);
});

router.patch('/users/:id/role', adminOnly, async (req, res) => {
  const { role } = req.body || {};
  if (!['user', 'admin'].includes(role))
    return res.status(400).json({ error: 'Invalid role' });
  const { rows } = await pool.query(
    'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, role',
    [role, req.params.id]
  );
  res.json(rows[0] || null);
});

router.delete('/users/:id', adminOnly, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ── Keys ──────────────────────────────────────────────────────────────────────

router.get('/keys', adminOnly, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT k.id, k.key_code, k.product, k.expires_at, k.active,
           k.hwid, k.hwid_bound_at, k.last_seen, k.note, k.created_at,
           u.username AS assigned_to, u.id AS user_id,
           a.username AS created_by_name
    FROM license_keys k
    LEFT JOIN users u ON u.id = k.user_id
    LEFT JOIN users a ON a.id = k.created_by
    ORDER BY k.created_at DESC
  `);
  res.json(rows);
});

// Generate a new key
router.post('/keys/generate', adminOnly, async (req, res) => {
  const { product, expires_at, user_id, note, count = 1 } = req.body || {};
  if (!product) return res.status(400).json({ error: 'product is required' });

  const n   = Math.min(Math.max(parseInt(count) || 1, 1), 50);
  const out = [];

  for (let i = 0; i < n; i++) {
    const key_code = genKeyCode();

    const { rows } = await pool.query(
      `INSERT INTO license_keys (key_code, product, user_id, expires_at, note, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (key_code) DO NOTHING
       RETURNING *`,
      [key_code, product, user_id || null, expires_at || null, note || null, req.user.id]
    );
    if (rows[0]) out.push(rows[0]);
  }

  res.json(out);
});

// Assign a key to a user
router.patch('/keys/:id/assign', adminOnly, async (req, res) => {
  const { user_id } = req.body || {};
  const { rows } = await pool.query(
    'UPDATE license_keys SET user_id = $1 WHERE id = $2 RETURNING *',
    [user_id || null, req.params.id]
  );
  res.json(rows[0] || null);
});

// Revoke / activate
router.patch('/keys/:id/active', adminOnly, async (req, res) => {
  const { active } = req.body || {};
  const { rows } = await pool.query(
    'UPDATE license_keys SET active = $1 WHERE id = $2 RETURNING *',
    [!!active, req.params.id]
  );
  res.json(rows[0] || null);
});

// Reset HWID
router.patch('/keys/:id/reset-hwid', adminOnly, async (req, res) => {
  const { rows } = await pool.query(
    'UPDATE license_keys SET hwid = NULL, hwid_bound_at = NULL WHERE id = $1 RETURNING *',
    [req.params.id]
  );
  res.json(rows[0] || null);
});

// Update expiry
router.patch('/keys/:id/expiry', adminOnly, async (req, res) => {
  const { expires_at } = req.body || {};
  const { rows } = await pool.query(
    'UPDATE license_keys SET expires_at = $1 WHERE id = $2 RETURNING *',
    [expires_at || null, req.params.id]
  );
  res.json(rows[0] || null);
});

// Delete key
router.delete('/keys/:id', adminOnly, async (req, res) => {
  await pool.query('DELETE FROM license_keys WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// Stats for admin overview
router.get('/stats', adminOnly, async (req, res) => {
  const [users, keys, active, expiring] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM users'),
    pool.query('SELECT COUNT(*) FROM license_keys'),
    pool.query('SELECT COUNT(*) FROM license_keys WHERE active = true'),
    pool.query(`SELECT COUNT(*) FROM license_keys WHERE active = true AND expires_at IS NOT NULL AND expires_at < NOW() + INTERVAL '7 days'`),
  ]);
  res.json({
    users:    parseInt(users.rows[0].count),
    keys:     parseInt(keys.rows[0].count),
    active:   parseInt(active.rows[0].count),
    expiring: parseInt(expiring.rows[0].count),
  });
});

module.exports = router;
