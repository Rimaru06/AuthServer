const express = require('express');
const  {signup , verifyEmail , login , refreshToken} = require('../controllers/authController');

const router = express.Router();

router.post('/signup', signup);
router.get('/verify-email', verifyEmail)
router.post('/login', login);
router.post('/refreshToken',refreshToken);



module.exports = router;