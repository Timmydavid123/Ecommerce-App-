const express = require('express');
const authController = require('../controllers/authController'); 
const passport = require('passport');
const extractUserId = require('../middleware/extractUserId');
const checkTokenExpiration = require('../middleware/checkTokenExpiration');
const multer = require('multer');

const router = express.Router();

// Set up storage for multer
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.post('/verify-email', authController.verifyEmail);
router.post('/reset-password', authController.resetPassword);
router.get('/logout', authController.logout);
router.post('/resend-otp', authController.resendOTP);
router.get('/user', extractUserId, authController.getUser);
router.get('/users/:userId', authController.getUser);

// New routes for Google authentication
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback route after successful Google Sign-In
router.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  // Redirect to the desired page after successful Google Sign-In
  res.redirect('/chat');
});

// New routes for profile picture
router.post('/upload-profile-picture', extractUserId, upload.single('profilePicture'), authController.uploadProfilePicture);
router.post('/update-profile-picture/:userId', extractUserId, upload.single('profilePicture'), authController.updateProfilePicture);

module.exports = router;
