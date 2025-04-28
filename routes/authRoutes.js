const express = require('express');
const  {signup , verifyEmail , login , refreshToken , logout , forgotPassword,resetPassoword, verifymfaOtp} = require('../controllers/authController');
const {authLimiter} = require('../middleware/rateLimiter')
const router = express.Router();

router.post('/signup', signup);
router.get('/verify-email', verifyEmail)
router.post('/login',authLimiter,login);
router.post('/refreshToken',refreshToken);
router.post('/logout',logout);
router.post('/forgotpassword',authLimiter ,forgotPassword);
router.post('/reset-password/:token',resetPassoword);
router.post('/verifymfaOtp',verifymfaOtp);

module.exports = router;