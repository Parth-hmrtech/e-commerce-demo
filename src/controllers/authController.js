const bcrypt = require('bcrypt');
const crypto = require('crypto');
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

    // Basic validation
    if (!password || typeof password !== 'string') {
        return res.status(400).json({ error: 'Password is required and must be a string' });
    }

    try {
        // Rest of your code
        const existingUser = await User.findByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const password_hash = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            first_name,
            last_name,
            email,
            password_hash,
            role,
            phone_number,
        });

        res.status(201).json({
            message: 'User registered successfully',
            user: newUser,
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: err.message || 'Something went wrong' });
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

    // ✅ Create JWT token (1 hour validity)
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // ✅ Store token in session
    req.session.token = token;

    // ✅ Optionally store user ID or role too
    req.session.userId = user.id;

    // ✅ Ensure cookie session matches token life
    // req.session.cookie.maxAge = 60 * 60 * 1000; // 1 hour

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
    const { first_name, last_name, email, phone_number } = req.body;

    if (!first_name || !last_name || !email || !phone_number) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    await User.updateProfile(req.user.id, {
      first_name,
      last_name,
      email,
      phone_number
    });

    res.json({ message: 'Profile updated successfully' });
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

        // Generate a random 8-character password (alphanumeric)
        const newPassword = crypto.randomBytes(6).toString('base64').slice(0, 8);

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update user's password in DB
        await User.forgotPassword(user.id, hashedPassword);

        // Send the new password via email
        await sendResetPasswordEmail(email, newPassword);

        res.json({ message: 'New password sent to your email' });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ error: 'Something went wrong' });
    }
};

exports.resetPassword = async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;

  if (!userId || !oldPassword || !newPassword) {
    return res.status(400).json({
      message: 'User ID, old password, and new password are required.'
    });
  }

  try {
    const user = await User.findById(userId, true); // Include password

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
    await User.resetPassword(userId, newPasswordHash);

    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
};