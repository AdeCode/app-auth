const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const validator = require('validator');
const bcrypt = require('bcrypt')

const authSchema = new Schema({
    email:{
        type: String,
        required: [true, 'email is required'],
        unique: true
    },
    firstName:{
        type: String,
        required: [true, 'firstname is required']
    },
    lastName:{
        type: String,
        required: [true, 'lastname is required']
    },
    password:{
        type: String,
        required: [true, 'email is required']
    },
}, {timestamps: true})

authSchema.statics.signUp = async function (email, firstName, lastName, password) {
    if(!email || !password){
        throw Error('All fields must be filled')
    }
    if(!validator.isEmail(email)){
        throw Error('Email is not a valid email')
    }
    if(!validator.isStrongPassword(password)){
        throw Error('Password is not strong enough')
    }
    const exists = await this.findOne({email})
    if(exists){
        throw Error('Email alreadyin use')
    }

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(password, salt)
    const user = await this.create({email, password: hash, firstName, lastName})
    console.log(user)
    return user
}

const Auth = mongoose.model('Auth', authSchema)
module.exports = Auth