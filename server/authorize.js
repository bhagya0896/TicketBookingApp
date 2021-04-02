
const jwt = require('jsonwebtoken');


function authenticate(req,res,next)
{
if(req.headers.authorization != undefined)
{
    jwt.verify(req.headers.authorization ,process.env.JWT_KEY,(err,decode)=>
{
    if(decode!==undefined)
    {
        console.log(decode);
        req.role = decode.role;
        next();   
    }else
    {
        res.status(403).json({"message":"invalid token"}) 
    }
})

}else{

    res.status(401).json({"message":"no token in headers"})
}

}






module.exports = {authenticate}