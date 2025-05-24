const express = require('express');
const session = require('express-session');
const authRoutes = require('./routes/authRoutes');
require('dotenv').config();

const app = express();

app.use(express.json());

// ✅ Set up session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret', // better to use .env
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 60 * 60 * 1000, // 1 hour in milliseconds
    httpOnly: true,         // helps prevent XSS
    secure: false           // set to true if using HTTPS
  }
}));

// ✅ Mount your auth routes
app.use('/auth', authRoutes);

module.exports = app;
  