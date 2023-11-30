const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  fullName: {
    type: String,
    required: true,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  passwordResetToken: {
    type: String,
  },
  passwordResetTokenExpiration: {
    type: Date,
  },
  emailVerificationOTP: {
    type: String,
  },
  profilePicture: {
    type: String,
  },
});

const User = mongoose.model('User', userSchema);

module.exports = { User };