const pool = require('../config/db');

module.exports = {
  async findByEmail(email) {
    const res = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return res.rows[0];
  },

  async create({ first_name, last_name, email, password_hash, role, phone_number }) {
    const res = await pool.query(
      `INSERT INTO users (first_name, last_name, email, password_hash, role, phone_number)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, first_name, last_name, email, role, phone_number, created_at`,
      [first_name, last_name, email, password_hash, role, phone_number]
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await pool.query(
      `SELECT id, first_name, last_name, email, role, phone_number, created_at 
       FROM users 
       WHERE id = $1 AND deleted_at IS NULL`,
      [id]
    );
    return res.rows[0];
  },

  async updateName(id, first_name, last_name) {
    await pool.query(
      'UPDATE users SET first_name = $1, last_name = $2, updated_at = NOW() WHERE id = $3',
      [first_name, last_name, id]
    );
  },

  async updatePassword(id, password_hash) {
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [password_hash, id]
    );
  },
};
