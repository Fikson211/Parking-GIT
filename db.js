const { Pool } = require('pg');

const useSSL = true; // для Railway Postgres почти всегда надо SSL

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

module.exports = { pool };
