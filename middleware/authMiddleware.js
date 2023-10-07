const jwt = require('jsonwebtoken');
const dotenv = require('dotenv').config();


function authMiddleware(req, res, next) {
    try {
        if (req.cookies && req.cookies.token) {
            const token = req.cookies.token;
            jwt.verify(token, process.env.JWT_SECRET, {}, async (err, userData) => {
                if (err) {
                    return res.status(401).json({
                        message: "Unauthorised"
                    })
                }
                req.user = userData;
                next();
            })
        } else {
            return res.status(401).json({
                message: "Unauthorised"
            })
        }
    } catch (err) {
        return res.status(401).json({
            message: "Unauthorised"
        })
    }
}

module.exports = {
    authMiddleware
}