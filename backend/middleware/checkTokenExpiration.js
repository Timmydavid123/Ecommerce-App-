// checkTokenExpiration.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

module.exports = (req, res, next) => {
  // Get the token from the request headers
  const token = req.headers.authorization;

  if (token) {
    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        // Token verification failed, indicating an expired token
        console.error('Token verification failed:', err);
        req.logout(); // Perform logout
      } else {

      
        const currentTime = Date.now(); // Current time in milliseconds
        const expirationTime = decoded.exp * 1000; // Convert seconds to milliseconds
        
        const oneDayInMilliseconds = 24 * 60 * 60 * 1000; // One day in milliseconds
        
        if (currentTime > expirationTime + oneDayInMilliseconds) {
          console.error('Token expired after one day.');
          req.logout(); // Perform logout
        }
      }
    });
  }

  next();
};
