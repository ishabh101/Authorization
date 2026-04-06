const jwt = require('jsonwebtoken');

module.exports = function(roles = []) {
  if (typeof roles === 'string') roles = [roles];
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.user = payload;
      if (roles.length && !roles.includes(payload.role)) return res.status(403).json({ message: 'Forbidden' });
      next();
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  };
};
