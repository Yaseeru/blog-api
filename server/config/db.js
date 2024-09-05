require("dotenv").config();
const mongoose = require("mongoose");

const connectDb = async () => {
    try {
        mongoose.set("strictQuery", false);
        const conn = await mongoose.connect(process.env.MONGODB_URI);
        console.log(`Database Connected: ${conn.connection.host}`);
    } catch (error) {
        console.log(`Error: ${error.message}`);
        process.exit(1); // Exit process with failure
    }
}

module.exports = connectDb;
