
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const twoFactorRoutes = require('./routes/twoFactorRoutes');

const app = express();
require('dotenv').config();
connectDB();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ message: 'Authenticator API is running' });
});

app.use('/api/auth', authRoutes);
app.use('/api/2fa', twoFactorRoutes);

module.exports = app;