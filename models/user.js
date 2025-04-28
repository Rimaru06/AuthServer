const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name : {
        type : String,
        required : true,
        trim : true,
    },
    email : {
        type : String,
        required : true,
        lowercase : true,
        unique : true
    },
    password : {
        type : String,
        required : true,
    },
    isVerified : {
        type : Boolean,
        default : false
    },
    verificationToken : String,
    verificationTokenExpiry : Date,

    passwordResetToken : String,
    passwordResetExpires : Date,

    mfaEnabled : {
        type : Boolean,
        default : false
    },

    mfaSecret : {
        type : String
    },
    mfaSecretExpires : Date,

    createdAt : {
        type : Date,
        default : Date.now
    }


})

module.exports = mongoose.model('User', userSchema);