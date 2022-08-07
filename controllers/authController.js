const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const sendEmail = require('./../utils/email');

//create the token with id as payload, using secret and expiration date that define in the .env file
const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

//
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  //cookie expires at:
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    //secure: true, //says that the cookie will sent only in encrypted connection(HTTPS)
    httpOnly: true //says that cookie cannot be accessed/modify in any way by the browser
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);

  // Remove password from output when user sign up
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

//MODIFY that only this params will be able to chang(cant change role to admin)
exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm //,
    // role: req.body.role //delete this at the end (so no one be able to become admin)
  });

  createSendToken(newUser, 201, res);
});

//CREATE login function + user validation
exports.login = catchAsync(async (req, res, next) => {
  //read email and password from the body
  //OPTION 1 : const email=req.body.email ...
  //better way :
  const { email, password } = req.body;

  // 1) Check if email and password exist at the req
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }
  // 2) Check if user exists && password is correct by using findOne filter obj
  const user = await User.findOne({ email }).select('+password'); //because by default not selected (I definiens userSchema select: false on pass)

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // 3) If everything ok, send token to client
  createSendToken(user, 200, res);
});

//PROTECT routes
exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check if it's there
  let token;
  if (
    //check if exists& start with Bearer
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1]; //split the array in order to take only the token
    //console.log(token); //GET all ->header ->key=auth value=bearer+token
  }
  //if there isnt token send general error message
  if (!token) {
    return next(
      new AppError(
        'You are not logged in! Please log in to get access (or add key=auth value=bearer+token to header).',
        401
      )
    );
  }
  // 2) Verification token
  //using promisify to make it return a promise
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  //console.log(decoded);

  // 3) Check if user still exists -(if not have this, if user was delete/updated details make sure to chang jwt too ..)
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError(
        'The user belonging to this token does no longer exist.',
        401
      )
    );
  }
  // 4) Check if user changed password after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    //iat-issued at
    return next(
      new AppError('User recently changed password! Please log in again.', 401)
    );
  }
  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser; //change current user data by input.
  next();
});

//middleware that let access to delete tours only to admin& lead-guid
exports.restrictTo = (...roles) => {
  //create an array of all the arguments I was specified( in order to sent params to middle)
  return (req, res, next) => {
    // roles ['admin', 'lead-guide']. role='user'
    if (!roles.includes(req.user.role)) {
      //req.user☝ is the current user that happened in the protect function
      return next(
        new AppError('You do not have permission to perform this action', 403) //403 -forbidden
      );
    }

    next();
  };
};

//connect to email service and send new token trow it.(mailTrap)
exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email address.', 404));
  }

  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false }); //will cancel all the validation that modified in schema (when we save the new)

  // 3) Send it to user's email
  //              HTTP/HTTPS👇
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;
  //in order to send the new token ☝in the routing url (based on User routes file)

  const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 min)',
      message
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!'
    });
    //In case email dont sent properly undefined the relevant fields
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false }); //cancel validation for this req

    return next(
      new AppError('There was an error sending the email. Try again later!'),
      500
    );
  }
});

//Patch -reset password by enter jwt that get from mail to the postman url.
exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token - crypt the new token that send to db (in case someone will huck db)
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  //find user by the new crypt token
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() } //$gt -greater operator
  });

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password; //reset user pass by req value
  user.passwordConfirm = req.body.passwordConfirm;
  //delete the reset token and the Expires time i get in the first step in this function
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save(); //save to db new values

  // 3) Update changedPasswordAt property for the user
  // 4) Log the user in, send JWT
  createSendToken(user, 200, res); //(function also in login signup)
});

//Update Password without forgetting the old one
exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get user from collection
  const user = await User.findById(req.user.id).select('+password'); //because by default not selected I definiens userschema select: false on pass

  // 2) Check if POSTed current password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  // 3) If so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  // User.findByIdAndUpdate will NOT work as intended!

  // 4) Log user in, send JWT
  createSendToken(user, 200, res);
});
