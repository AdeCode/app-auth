require('dotenv').config()
const express = require('express')
const connectDB = require('./db')
const authRoutes = require('./routes/auth')

const mongoose = require('mongoose')

//express app
const app = express()

app.use(express.json())

//routes
app.use('/api', authRoutes)

app.listen(process.env.PORT, ()=>{
    console.log('listening on port '+ process.env.PORT)
})

connectDB()