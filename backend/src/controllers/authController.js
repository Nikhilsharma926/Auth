const jwt = require('jsonwebtoken');

const User = require('../models/User');

const generateOTP = require('../utils/generateOTP');
const sendEmail = require('../utils/sendEmail');

const generateToken = (id) => {
  return jwt.sign(
    { id },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRE,
    }
  );
};



// SIGNUP
const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    let user = await User.findOne({ email });

    if (user && user.isEmailVerified) {
      return res.status(400).json({
        message: 'User already exists',
      });
    }

    if (user) {
      user.name = name;
      user.password = password;
    } else {
      user = new User({
        name,
        email,
        password,
      });
    }

    const otp = generateOTP();

    user.emailOtp = otp;
    user.emailOtpExpires = Date.now() + 10 * 60 * 1000;

    await user.save();

    await sendEmail({
      to: email,
      subject: 'Email Verification OTP',
      html: `
        <h2>Your OTP Code</h2>
        <h1>${otp}</h1>
        <p>OTP valid for 10 minutes.</p>
      `,
    });

    res.status(200).json({
      message: 'OTP sent successfully',
    });

  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};



// VERIFY EMAIL OTP
const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    if (
      user.emailOtp !== otp ||
      user.emailOtpExpires < Date.now()
    ) {
      return res.status(400).json({
        message: 'Invalid or expired OTP',
      });
    }

    user.isEmailVerified = true;

    user.emailOtp = undefined;
    user.emailOtpExpires = undefined;

    await user.save();

    const token = generateToken(user._id);

    res.json({
      token,
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



// LOGIN
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email })
      .select('+password');

    if (!user) {
      return res.status(401).json({
        message: 'Invalid credentials',
      });
    }

    if (!user.isEmailVerified) {
      return res.status(401).json({
        message: 'Please verify email first',
      });
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(401).json({
        message: 'Invalid credentials',
      });
    }

    // IMPORTANT FOR 2FA
    if (user.twoFactorEnabled) {
      return res.json({
        twoFactorRequired: true,
        userId: user._id,
      });
    }

    const token = generateToken(user._id);

    res.json({
      token,
      twoFactorRequired: false,
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



// PROFILE
const getProfile = async (req, res) => {
  try {

    const user = await User.findById(req.user._id);

    res.json({
      user,
    });

  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};



module.exports = {
  signup,
  verifyOTP,
  login,
  getProfile,
};