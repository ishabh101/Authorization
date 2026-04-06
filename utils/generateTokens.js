const jwt = require('jsonwebtoken');

const generateAccessToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

module.exports = { generateAccessToken, generateRefreshToken };
