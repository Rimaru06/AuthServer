const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendEmail = require('../services/emialService');


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

        const accessToken = jwt.sign({userId : user._id}, process.env.JWT_SECRET , {expiresIn : '15m'});
        const refreshToken = jwt.sign({userId : user._id} ,process.env.JWT_SECRET , {expiresIn : '7d'});

        res.cookie('accessToken',accessToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : 'Strict',
            maxAge : 15* 60 * 1000 // 15 min
        }).cookie('refreshToken', refreshToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : 'Strict',
            maxAge : 7 * 24 * 60 * 60 * 1000 // 7d
        }).status(200).json({message : 'Login Successful',user : {id : user._id , name : user.name , email : user.email}});

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