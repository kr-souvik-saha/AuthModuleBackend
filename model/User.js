const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    firstName: {
        type: String,
        required: [true, 'Firstname is required']
    },
    lastName: {
        type: String,
        required: [true, 'Last name is required']
    },
    userName: {
        type: String,
        required: [true, 'Username is required'],
        unique: [true, 'Username need to be unique']
    },
    password: {
        type: String,
        required: [true, 'Password is required']
    },
}, {
    timestamps: true
});

module.exports = mongoose.model('User', userSchema);