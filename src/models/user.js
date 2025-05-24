const dbConnect = require('../config/db');
const { register } = require('../controllers/authController');

module.exports = {

  async findByEmail(email) {
    const res = await dbConnect.query('SELECT * FROM users WHERE email = $1', [email]);
    return res.rows[0];
  },
  async registerUser({ first_name, last_name, email, password_hash, role, phone_number }) {
    const res = await dbConnect.query(
      `INSERT INTO users (first_name, last_name, email, password_hash, role, phone_number)
        VALUES (${first_name}, ${last_name}, ${email}, ${password_hash}, ${role}, ${phone_number})`
    );
    return res.rows[0];
  },
  // async getPeofile()

  async findById(id, includePassword = false) {
    const fields = includePassword
      ? 'id, first_name, last_name, email, password_hash, role, phone_number, created_at'
      : 'id, first_name, last_name, email, role, phone_number, created_at';

    const res = await dbConnect.query(
      `SELECT ${fields} FROM users WHERE id = $1 AND deleted_at IS NULL`,
      [id]
    );
    return res.rows[0];
  },

  async updateProfile(id, { first_name, last_name, email, phone_number }) {
    try {
      await dbConnect.query(
        `UPDATE users 
       SET first_name = $1, last_name = $2, email = $3, phone_number = $4, updated_at = NOW() 
       WHERE id = $5`,
        [first_name, last_name, email, phone_number, id]
      );
    } catch (err) {
      console.error('Database updateProfile error:', err);
      throw err;
    }
  },

  async resetPassword(id, password_hash) {
    await dbConnect.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [password_hash, id]
    );
  },
  async forgotPassword(id, password_hash) {
    await dbConnect.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [password_hash, id]
    );
  },
};
