const mongoose = require('mongoose');
const argon2 = require('argon2');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });   
// Hash password before saving
userSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        try {
            this.password = await argon2.hash(this.password);
        } catch (error) {
            return next(error);
        }
    }
    next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
    try {
        return await argon2.verify(this.password, candidatePassword);
    } catch (error) {
        throw new Error('Password comparison failed');
    }   
}

userSchema.index({ username: "text" });



const User = mongoose.model('User', userSchema);

module.exports = User;  