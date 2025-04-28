const jwt = require('jsonwebtoken');

const sendToken = (user,res) => {
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

}
module.exports = sendToken;