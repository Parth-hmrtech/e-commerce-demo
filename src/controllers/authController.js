const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { generateToken } = require('../utils/tokenHelper');
const { sendResetPasswordEmail } = require('../services/emailService');
const pool = require('../config/db');
const JWT_SECRET = process.env.JWT_SECRET;


exports.register = async (req, res) => {

    const {
        first_name,
        last_name,
        email,
        password,
        role = 'buyer',
        phone_number,
    } = req.body;

    try {
        // Hash the password
        const password_hash = await bcrypt.hash(password, 10);

        // Insert user into the database
        const result = await pool.query(
            `INSERT INTO users 
       (first_name, last_name, email, password_hash, role, phone_number)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, first_name, last_name, email, role, phone_number, created_at`,
            [first_name, last_name, email, password_hash, role, phone_number]
        );

        const user = result.rows[0];
        res.status(201).json({ message: 'User registered successfully', user });
    } catch (err) {
        console.error('Register error:', err);

        if (err.code === '23505') {
            // PostgreSQL unique violation error code
            res.status(400).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: 'Something went wrong' });
        }
    }

};


exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const user = result.rows[0];

        if (!password || !user.password_hash) {
            return res.status(400).json({ error: 'Password not provided or missing from database' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // ✅ Generate JWT token with 2 minutes expiry
        const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // ✅ Only store the token in the session
        req.session.token = token;

        // ✅ Set session cookie maxAge to 2 minutes
        req.session.cookie.maxAge = 2 * 60 * 1000;

        return res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Something went wrong' });
    }
};

exports.logout = (req, res) => {
    if (!req.session || !req.session.token) {
        // User not logged in or no session token
        return res.status(400).json({ message: 'You are not logged in' });
    }

    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Could not log out' });
        }
        // Successfully logged out
        res.json({ message: 'Logged out successfully' });
    });
};

exports.profile = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const { password_hash, ...safeUser } = user;

        res.json(safeUser);
    } catch (err) {
        console.error('Profile fetch error:', err);  // detailed error log
        res.status(500).json({ error: 'Something went wrong' });
    }
};

exports.updateProfile = async (req, res) => {
    try {
        const { first_name, last_name } = req.body;

        if (!first_name || !last_name) {
            return res.status(400).json({ error: 'Both first_name and last_name are required' });
        }

        await User.updateName(req.user.id, first_name, last_name);
        res.json({ message: 'Profile updated' });
    } catch (err) {
        console.error('Update profile error:', err);
        res.status(500).json({ error: 'Something went wrong' });
    }
};


exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findByEmail(email);

        if (!user) return res.status(404).json({ message: 'User not found' });

        const token = generateToken({ id: user.id }, '15m');
        await sendResetPasswordEmail(email, token);

        res.json({ message: 'Reset email sent' });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ error: 'Something went wrong' });
    }
};

exports.resetPassword = async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;

  if (!userId || !oldPassword || !newPassword) {
    return res.status(400).json({ message: 'User ID, old password, and new password are required.' });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (!user.password_hash) {
      return res.status(400).json({ message: 'Password data missing for user.' });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Old password is incorrect.' });
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    await User.updatePassword(userId, newPasswordHash);

    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
};
