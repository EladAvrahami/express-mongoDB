const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name!']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  photo: String,
  //types of roles
  role: {
    type: String,
    enum: ['user', 'guide', 'lead-guide', 'admin'], //use enum to only get this types of users
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false //dont show the password in any req (except the ones who i use select like update/login)
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      // This only works on CREATE and SAVE!!!
      //check if passwordConfirm =password
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!'
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  //to expire the reset token from getting access to user detail in the db
  passwordResetExpires: Date,
  //in order to check if user delete himself from the app (but not actually delete its details from db)
  active: {
    type: Boolean,
    default: true,
    select: false
  }
});

//THIS 3 "pre" Middleware WILL BE CHECKED EVERY TIME I SAVE TO DB !!!(just like updatePassword and resetPassword in authCont..)

//bcrypt middle that run between getting the data and saving it encrypted to DB
/*userSchema.pre('save', async function(next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12 - bigger the num better encrypt but tack more time to save on db.
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field .
  this.passwordConfirm = undefined;
  next();
});*/

//Middleware that check if user not modify the password and (except when creating new one)
// in order to not change the passwordChangedAt property
userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

//start this middle in every query that starts with the word 'find' (using^)
userSchema.pre(/^find/, function(next) {
  // this points to the current query
  this.find({ active: { $ne: false } }); //ne-not equal's to false
  next();
});

//bcrypt method that covert encrypted password to normal in order to be able to compare the one in the db
userSchema.methods.correctPassword = async function(
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

//add timeStemp to the jwt
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  //if passwordChangedAt is in the schema
  if (this.passwordChangedAt) {
    //parseInt - convert from mil sec
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp; //check that the time token created less than time that changed
  }

  // False means NOT changed
  return false;
};

//relevant to authController.forgotPassword stage 2
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  console.log({ resetToken }, this.passwordResetToken);
  //password reset req expires in 10 min
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
