const { Pool } = require('pg');
require('dotenv').config(); // Načíta údaje zo súboru .env

const pool = new Pool({
  user: process.env.DB_USER,       // napr. postgres
  host: process.env.DB_HOST,       // localhost
  database: process.env.DB_NAME,   // názov tvojej databázy (napr. buddgie_db)
  password: process.env.DB_PASSWORD, // tvoje heslo
  port: process.env.DB_PORT,       // 5432
});

module.exports = pool;