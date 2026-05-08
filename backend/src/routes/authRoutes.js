const express = require('express');

const {
  signup,
  verifyOTP,
  login,
  getProfile,
} = require('../controllers/authController');

const { protect } = require('../middleware/auth');

const router = express.Router();

router.post('/signup', signup);
router.post('/verify-otp', verifyOTP);
router.post('/login', login);

router.get('/profile', protect, getProfile);

module.exports = router;