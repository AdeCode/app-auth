const mongoose = require('mongoose');
require('dotenv').config();
const {DB_URI} = process.env

const connectDB = async () => {
    try{
        await mongoose.connect(`${DB_URI}`, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('MongoDB connected')
    }catch(err){
        console.error(err.message);
        process.exit(1);
    }
}

module.exports = connectDB