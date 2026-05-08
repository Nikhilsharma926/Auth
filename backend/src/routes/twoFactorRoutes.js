const express = require('express');

const {
  setupTwoFactor,
  verifyAndEnableTwoFactor,
  verifyLoginTwoFactor,
  disableTwoFactor,
} = require('../controllers/twoFactorController');

const { protect } = require('../middleware/auth');

const router = express.Router();

router.post('/setup', protect, setupTwoFactor);
router.post('/verify-enable', protect, verifyAndEnableTwoFactor);
router.post('/verify-login', verifyLoginTwoFactor);
router.post('/disable', protect, disableTwoFactor);

module.exports = router;