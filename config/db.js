const { default: mongoose } = require('mongoose');
const coonnectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        })
        console.log('MongoDB connected');
    } catch (error) {
        console.error('MongoDB connection error:', error);
      //  process.exit(1); // Exit the process with failure
    }
}

module.exports = coonnectDB;