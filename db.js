const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          SERIAL PRIMARY KEY,
      username    VARCHAR(50)  UNIQUE NOT NULL,
      email       VARCHAR(255) UNIQUE NOT NULL,
      password    VARCHAR(255) NOT NULL,
      role        VARCHAR(20)  NOT NULL DEFAULT 'user',
      created_at  TIMESTAMPTZ  DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_keys (
      id            SERIAL PRIMARY KEY,
      key_code      VARCHAR(60)  UNIQUE NOT NULL,
      product       VARCHAR(100) NOT NULL DEFAULT 'rage.lua',
      user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
      expires_at    TIMESTAMPTZ,
      hwid          VARCHAR(255),
      hwid_bound_at TIMESTAMPTZ,
      last_seen     TIMESTAMPTZ,
      active        BOOLEAN      NOT NULL DEFAULT true,
      note          TEXT,
      created_at    TIMESTAMPTZ  DEFAULT NOW(),
      created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL
    )
  `);
}

module.exports = { pool, initDb };
