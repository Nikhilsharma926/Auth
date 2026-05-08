const QRCode = require('qrcode');
const { authenticator } = require('otplib');
const User = require('../models/User');
const jwt = require('jsonwebtoken');


// GENERATE JWT
const generateToken = (id) => {
  return jwt.sign(
    { id },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRE,
    }
  );
};



// SETUP 2FA
const setupTwoFactor = async (req, res) => {
  try {

    const user = await User.findById(req.user._id)
      .select('+twoFactorSecret');

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    // SECRET GENERATE
    const secret = authenticator.generateSecret();

    user.twoFactorSecret = secret;

    await user.save();

    // APP NAME
    const appName = 'Authenticator App';

    // OTPAUTH URL
    const otpAuthUrl = authenticator.keyuri(
      user.email,
      appName,
      secret
    );

    // QR IMAGE
    const qrCodeImage = await QRCode.toDataURL(otpAuthUrl);

   res.json({
  secret,
  otpAuthUrl,
  qrCodeImage,
});

  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};



// VERIFY & ENABLE 2FA
const verifyAndEnableTwoFactor = async (req, res) => {
  try {

    const { token } = req.body;

    const user = await User.findById(req.user._id)
      .select('+twoFactorSecret');

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    const isValid = authenticator.verify({
      token,
      secret: user.twoFactorSecret,
    });

    if (!isValid) {
      return res.status(400).json({
        message: 'Invalid authenticator code',
      });
    }

    user.twoFactorEnabled = true;

    await user.save();

    res.json({
      message: '2FA enabled successfully',
    });

  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};



// VERIFY LOGIN 2FA
const verifyLoginTwoFactor = async (req, res) => {
  try {

    const { userId, token } = req.body;

    const user = await User.findById(userId)
      .select('+twoFactorSecret');

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    const isValid = authenticator.verify({
      token,
      secret: user.twoFactorSecret,
    });

    if (!isValid) {
      return res.status(400).json({
        message: 'Invalid authenticator code',
      });
    }

    const jwtToken = generateToken(user._id);

    res.json({
      token: jwtToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });

  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};



// DISABLE 2FA
const disableTwoFactor = async (req, res) => {
  try {

    const user = await User.findById(req.user._id);

    user.twoFactorEnabled = false;

    user.twoFactorSecret = undefined;

    await user.save();

    res.json({
      message: '2FA disabled successfully',
    });

  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};



module.exports = {
  setupTwoFactor,
  verifyAndEnableTwoFactor,
  verifyLoginTwoFactor,
  disableTwoFactor,
};