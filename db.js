const { Pool } = require('pg');

const connectionString =
  process.env.DATABASE_URL || process.env.DATABASE_URL;

console.log('DATABASE_URL exists?', !!process.env.DATABASE_URL);
console.log('DATABASE_URL exists?', !!process.env.DATABASE_URL);
console.log('Using DB var:', process.env.DATABASE_URL ? 'DATABASE_URL' : (process.env.DATABASE_URL ? 'DATABASE_URL' : 'NONE'));

const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false },
});

module.exports = { pool };
