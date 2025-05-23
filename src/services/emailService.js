const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.sendResetPasswordEmail = (to, token) => {
  const resetLink = `http://localhost:3000/reset-password?token=${token}`;
  return transporter.sendMail({
    to,
    subject: 'Password Reset',
    text: `Reset your password using this link: ${resetLink}`,
  });
};
