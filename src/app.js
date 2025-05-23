const express = require('express');
const session = require('express-session');
const authRoutes = require('./routes/authRoutes');
require('dotenv').config();

const app = express();
app.use(express.json());


app.use(session({
  secret: 'your_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 2 * 60 * 1000 } // 2 minutes
}));

// Then your routes and middleware
app.use('/auth', authRoutes);


module.exports = app
