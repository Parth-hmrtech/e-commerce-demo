const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.sendResetPasswordEmail = (to, newPassword) => {
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your New Password',
    text: `Your password has been reset. Your new temporary password is:\n\n${newPassword}\n\nPlease login and change it immediately.`,
  }).then(info => {
    console.log('Reset password email sent:', info.response);
  }).catch(err => {
    console.error('Error sending reset password email:', err);
    throw err;
  });
};
