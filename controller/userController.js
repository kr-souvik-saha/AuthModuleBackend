const bcrypt = require('bcryptjs');
const User = require('../model/User');
const jwt = require('jsonwebtoken');

const jwtSecret = process.env.JWT_SECRET


const register = async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            userName,
            password
        } = req.body;



        if (!firstName || !lastName || !userName || !password) {
            res.status(400).json({
                message: "All The fields are required"
            });
            return
        }

        const userAvailable = await User.findOne({
            userName
        });

        if (userAvailable) {
            res.status(400).json({
                message: 'User already exists'
            });
            return
        }
        const hashedPassword = await bcrypt.hash(password, 10);

        const createUser = await User.create({
            firstName,
            lastName,
            userName,
            password: hashedPassword
        });

        const token = jwt.sign({
            userId: createUser._id,
            userName
        }, jwtSecret, {
            expiresIn: '10h'
        });

        res.cookie('token', token, {
            expires: new Date(Date.now() + 3600000)
        }).status(200).json({
            id: createUser._id
        })

    } catch (err) {
        res.status(400).json(err);
    }

}

const login = async (req, res) => {
    try {
        const {
            userName,
            password
        } = req.body;


        if (!userName || !password) {
            res.status(401).json({
                message: 'All fields are required'
            });
        }
        findUser = await User.findOne({
            userName
        });

        if (findUser) {
            const passOk = await bcrypt.compare(password, findUser.password);

            if (passOk) {
                const token = jwt.sign({
                    userId: findUser._id,
                    userName
                }, jwtSecret, {
                    expiresIn: "10h"
                });

                res.status(200).cookie('token', token, {
                    expires: new Date(Date.now() + 3600000)
                }).json({
                    id: findUser._id
                });
            } else {
                res.status(401).json({
                    message: "Invalid Credentials"
                })
            }
        } else {
            res.status(401).json({
                message: "Invalid Credentials"
            })
        }
    } catch (err) {
        res.status(401).json(err)
    }

}

const profile = async (req, res) => {
    try {

        if (req.cookies && req.cookies.token) {
            const token = req.cookies.token;
            jwt.verify(token, jwtSecret, {}, async (err, userData) => {
                if (err) {
                    res.status(401).json({
                        message: "Unauthorised"
                    })
                }
                const userName = userData.userName;
                const findUser = await User.findOne({
                    userName
                });
                const resUser = {
                    id: findUser._id,
                    firstName: findUser.firstName,
                    lastName: findUser.lastName,
                    userName: findUser.userName
                }
                res.status(200).json(resUser)
            })
        } else {

            res.status(401).json({
                message: "Unauthorised"
            })
        }
    } catch (err) {
        res.status(401).json(err)
    }

}

const logout = async (req, res) => {
    res.clearCookie('token').status(200).json({
        message: 'Logged Out'
    });
}

module.exports = {
    register,
    login,
    profile,
    logout
}