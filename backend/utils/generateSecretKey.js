const crypto = require('crypto');
const jwtSecretKey = crypto.randomBytes(32).toString('hex');
const sessionSecretKey = crypto.randomBytes(32).toString('hex');

console.log(`JWT_SECRET=${jwtSecretKey}`);
console.log(`SESSION_SECRET=${sessionSecretKey}`);