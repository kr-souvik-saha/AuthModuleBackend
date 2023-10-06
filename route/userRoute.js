const express = require('express');
const {
    register,
    login,
    profile,
    logout
} = require('../controller/userController');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/profile', profile);
router.get('/logout', logout);

exports.router = router;