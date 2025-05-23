const { Pool } = require('pg');

// Directly set DB config without using environment variables
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'ecommerce-demo',
  password: 'postgres',  // must be a string
  port: 5432,
});

console.log('DB_PASS: postgres');  // hardcoded debug

module.exports = pool;
