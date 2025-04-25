const jwt = require('jsonwebtoken');

const authenticate = (req,res,next) =>{
    const token = req.cookies.accessToken;
    if(!token) return res.status(401).json({message : 'Unauthorized. No token !'});

    try {
        const decoded = jwt.verify(token,process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({message : 'Invalid or expired token. '});
    }
}

module.exports = authenticate;