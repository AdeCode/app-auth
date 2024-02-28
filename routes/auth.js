const express = require('express');
const router = express.Router();
const {createUser, userLogin, getData, generate2fa, verifyOtp} = require('../controllers/authController');
const requireAuth = require('../middleware/authenticator')

router.get('/', function (req, res) {
    res.json({message:'Welcome to auth app'})
})

router.post('/signup', createUser)

router.post('/login', userLogin)

router.get('/2fa/generate', generate2fa)

router.post('/verify-otp', verifyOtp)


//require auth for all workout routes
router.use(requireAuth)

router.get('/get-data', getData)

module.exports = router