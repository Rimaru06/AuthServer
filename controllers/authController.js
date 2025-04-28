const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendEmail = require('../services/emialService');
const crypto = require('crypto');
const sendToken = require('../utils/sendToken');


exports.signup = async (req,res) => {
    try {
        const {name , email , password} = req.body;
        if(!name || !email || !password)
        {
          return res.status(400).json({message : "All feild are required"});
        }

        const existinguser = await User.findOne({email});
        if(existinguser) return res.status(409).json({message : 'user already exists'});

        const hashedPassword = await bcrypt.hash(password,10);

        const verificationToken = jwt.sign({email} , process.env.JWT_SECRET, {expiresIn : '1h'});

        const user = await User.create({
            name,
            email,
            password : hashedPassword,
            verificationToken,
            verificationTokenExpiry : Date.now() + 3600000 // 1hr
        })

        const verificationURL = `${process.env.CLIENT_URL}/verify-email?token=${verificationToken}`
        await sendEmail({
            to : email,
            subject : 'Verify your email',
            html : `<p> Click <a href="${verificationURL}">here</a> to verify your email.</p>`,
        });

        res.status(201).json({
            message : "Signup successful, Please check your email to verify your account."
        })
    } catch (error) {
        console.error('Signup error',error.message);
        res.status(500).json({message : 'Server error'});
    }
}


exports.verifyEmail = async (req,res) => {
    const token = req.query.token;
    if(!token) return res.status(400).json({message : 'verification token missing'});
    try {
        const decoded = jwt.verify(token , process.env.JWT_SECRET);
        const user = await User.findOne({
            email : decoded.email,
            verificationToken : token,
            verificationTokenExpiry : {$gt : Date.now()} 
        })
        if(!user) return res.status(400).json({message : 'invalid or expired token'});

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpiry = undefined
        await user.save();

        res.status(200).json({message : 'Email verfied succesfully. you can now log in'});
    } catch (error) {
        console.error(error);
        return res.status(400).json({message : 'Invalid Token'})
    }
}

exports.login = async (req,res) => {
    const {email , password} = req.body;
    if(!email || !password) return res.status(400).json({message : 'Email and password are required'});

    try {
        const user = await User.findOne({
            email
        })
        if(!user) return res.status(401).json({message : 'Invalid Credentails'});

        if(!user.isVerified) return res.status(401).json({message : 'please verify your email'});

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch) return res.status(401).json({message : 'Invalid Credentails'});

        if(user.mfaEnabled)
        {
            const otp = Math.floor(100000,Math.random() * 900000).toString();
            user.mfaSecret = crypto.createHash('sha256').update(otp).digest('hex');
            user.mfaSecretExpires = Date.now() + 5 * 60 * 1000 // 5 min
            await user.save();

            await sendEmail({
                to : user.email,
                subject : "your otp code",
                html : `<p> your otp is ${otp} </p>`
            })

            return res.status(200).json({message : 'otp sent. please verfiy to complete login'});
        }

        sendToken(user,res);
    } catch (error) {
        console.error('Login error',error);
        return res.status(500).json({message : 'Server Error'});
    }
}

exports.refreshToken = (req,res) => {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) return res.status(401).json({message : 'No refresh Token provided'});

    try {
        const decoded = jwt.verify(refreshToken,process.env.JWT_SECRET);
        const newAccessToken = jwt.sign({userId : decoded.userId},process.env.JWT_SECRET,{expiresIn : '15m'});

        res.cookie('accessToken',newAccessToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : 'Strict',
            maxAge : 15 * 60 * 1000 // 15 min
        }).status(200).json({message : 'Access Token refreshed'});
    } catch (error) {
        return res.status(403).json({message : 'Invalid or expired refresh Token'})
    }
}

exports.logout = (req,res) => {
    res.clearCookie('accessToken', {
        httpOnly : true,
        secure : process.env.NODE_ENV === 'production',
        sameSite : 'Strict'
    }).clearCookie('refreshToken',{
        httpOnly : true,
        secure : process.env.NODE_ENV === 'production',
        sameSite : 'Strict'
    }).status(200).json({message : "Logged out successfully"})
}


exports.forgotPassword = async (req,res) => {
    const {email} = req.body;
    try {
        const user = await User.findOne({email});
        if(!user) return res.status(404).json({message : 'user not found'});

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        const resetTokenExpiry = Date.now() + 15 * 60 * 1000 // 15 min
        
        user.passwordResetToken = resetTokenHash;
        user.passwordResetExpires = resetTokenExpiry;

        await user.save();

        const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
        await sendEmail({
            to : user.email,
            subject : 'reset password request',
            html : `<p> Click <a href="${resetUrl}">here</a> reset your password.</p>`,
        })

        res.status(200).json({message : 'reset password link sent to your email'})
    } catch (error) {
        console.error('error : ', error);
        return res.status(500).json({message : 'server error in forgot password'});
    }
}

exports.resetPassoword = async (req,res) => {
    const {token} = req.params;
    const {newPassword} = req.body;

    try {
        const resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');

        const user = await User.findOne({
            passwordResetToken : resetTokenHash,
            passwordResetExpires : { $gt : Date.now()}
        })

        if(!user) return res.status(404).json({message : "resettoken Invalid or expired"});

        const hashedPassword = await bcrypt.hash(newPassword,10);

        user.password = hashedPassword
        user.passwordResetToken = undefined
        user.passwordResetExpires = undefined

        await user.save();

        res.status(200).json({message : "password reset successfully"});
    } catch (error) {
        console.error('reset password : ',error);
        return res.status(500).json({message : 'server error in reset password'})
    }


}

exports.verifymfaOtp = async (req,res) => {
    const {email, otp} = req.body;
    try {
        const user = await User.findOne({
            email
        })

        if(!user) return res.status(400).json({message : "Invalid Request"});

        const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');

        if(user.mfaSecret !== hashedOtp || user.mfaSecretExpires < Date.now())
            return res.status(400).message({message : 'Invalid or expired OTP'});

        user.mfaSecret = undefined;
        user.mfaSecretExpires = undefined;

        await user.save();

        sendToken(user,res);
    } catch (error) {
        console.error('verifymfaotp error : ',error);
        return res.status(500).json({message : 'Server Error'}); 
    }
}

