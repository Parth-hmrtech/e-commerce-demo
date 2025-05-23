const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key';

exports.verifySessionJWT = (req, res, next) => {
  const token = req.session?.token;
console.log(token);

  if (!token) {
    // No token in session, user not logged in
    return res.status(401).json({ message: 'Please log in' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // Token exists but invalid or expired
    req.session.destroy(() => {});
    return res.status(401).json({ message: 'Token expired' });
  }
};
