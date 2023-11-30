// extractUserId.js

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

const extractUserId = (req, res, next) => {
  try {
    const token = req.header('x-auth-token');

    if (!token) {
      return res.status(401).json({ message: 'Authorization denied. Token not found.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error('Error extracting user ID:', error);
    res.status(500).json({ message: 'Internal Server Error extracting user ID' });
  }
};

module.exports = extractUserId;
