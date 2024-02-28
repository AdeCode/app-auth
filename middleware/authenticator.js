const jwt = require('jsonwebtoken')
const UserAuth = require('../models/userModel')

const requireAuth = async(req, res, next) => {
    //verify authentication
    const {authorization} = req.headers

    if(!authorization){
        return res.status(401).json({error: 'Authorization token is required'})
    }

    const token = authorization.split(' ')[1]
    try{
        const {id} = jwt.verify(token, process.env.SECRET)
        const _id = id
        req.user = await UserAuth.findOne({_id}).select('_id')
        next()
    }catch(error){
        console.log(error)
        res.status(401).json({error:'Request not authorized'})
    }
    'Bearer'

}

module.exports = requireAuth