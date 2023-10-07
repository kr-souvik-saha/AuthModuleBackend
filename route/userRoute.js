const express = require('express');
const {
    register,
    login,
    profile,
    logout,
    miniProfile
} = require('../controller/userController');
const {
    authMiddleware
} = require('../middleware/authMiddleware');


const router = express.Router();


router.post('/register', register);
router.post('/login', login);
router.get('/profile', authMiddleware, profile);
router.get('/miniProfile', authMiddleware, miniProfile);
router.get('/logout', logout);

exports.router = router;