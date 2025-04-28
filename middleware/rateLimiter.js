const rateLimit = require('express-rate-limit');

exports.authLimiter = rateLimit({
    windowMs : 15 * 60 * 1000,
    max : 5,
    message : {
        meesage : 'Too many attempts. please try again after 15 minutes'
    },
    standardHeaders : true,
    legacyHeaders : false
})