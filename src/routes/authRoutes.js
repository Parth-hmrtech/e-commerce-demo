const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { verifySessionJWT } = require('../middlewares/authMiddleware');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.get('/profile', verifySessionJWT, authController.profile);
router.put('/profile', verifySessionJWT, authController.updateProfile);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

module.exports = router;
