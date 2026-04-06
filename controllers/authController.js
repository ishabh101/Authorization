const bcrypt = require('bcrypt');
const User = require('../models/User');
const { generateAccessToken, generateRefreshToken } = require('../utils/generateTokens');

exports.signup = async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'Email already used' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash, role: role || 'user' });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();
    res.json({
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      accessToken, refreshToken
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).json({ message: 'Missing fields' });
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Invalid credentials' });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();
    res.json({ accessToken, refreshToken, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.refresh = async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: 'No token' });
  try {
    const jwt = require('jsonwebtoken');
    const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(payload.id);
    if (!user || user.refreshToken !== token) return res.status(403).json({ message: 'Invalid refresh token' });
    const accessToken = generateAccessToken(user);
    res.json({ accessToken });
  } catch (err) {
    return res.status(401).json({ message: 'Invalid refresh token' });
  }
};

exports.forgetPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'No such user' });
  const token = Math.floor(100000 + Math.random() * 900000).toString();
  user.resetToken = token;
  await user.save();
  // Simulate email by logging to server console
  console.log(`Password reset token for ${email}: ${token}`);
  res.json({ message: 'Reset token generated (check server console in dev)' });
};

exports.resetPassword = async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) return res.status(400).json({ message: 'Missing fields' });
  const user = await User.findOne({ email });
  if (!user || user.resetToken !== token) return res.status(400).json({ message: 'Invalid token' });
  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = null;
  await user.save();
  res.json({ message: 'Password updated' });
};

exports.protectedSample = (req, res) => {
  res.json({ message: `Hello ${req.user.id}, your role is ${req.user.role}` });
};
