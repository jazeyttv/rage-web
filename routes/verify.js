// rage.lua compatibility endpoint — POST /verify { key, hwid }
const router   = require('express').Router();
const { pool } = require('../db');

router.post('/verify', async (req, res) => {
  const { key, hwid } = req.body || {};
  if (!key || !hwid) return res.json({ ok: false, msg: 'Missing key or hwid' });

  try {
    const { rows } = await pool.query(
      'SELECT * FROM license_keys WHERE key_code = $1',
      [key.trim()]
    );
    const entry = rows[0];
    if (!entry)    return res.json({ ok: false, msg: 'Unknown key' });
    if (!entry.active) return res.json({ ok: false, msg: 'Key revoked' });

    // Expiry check
    if (entry.expires_at && new Date(entry.expires_at) < new Date())
      return res.json({ ok: false, msg: 'Key expired' });

    // First use — bind HWID
    if (!entry.hwid) {
      await pool.query(
        'UPDATE license_keys SET hwid = $1, hwid_bound_at = NOW(), last_seen = NOW() WHERE id = $2',
        [hwid, entry.id]
      );
      return res.json({ ok: true, msg: 'Key activated' });
    }

    // HWID mismatch
    if (entry.hwid !== hwid) return res.json({ ok: false, msg: 'HWID mismatch' });

    await pool.query('UPDATE license_keys SET last_seen = NOW() WHERE id = $1', [entry.id]);
    res.json({ ok: true, msg: 'OK' });
  } catch (e) {
    console.error(e);
    res.json({ ok: false, msg: 'Server error' });
  }
});

module.exports = router;
