const express = require('express');
const morgan = require('morgan'); //help create log file
const rateLimit = require('express-rate-limit'); //npm i express-rate-limit
const helmet = require('helmet'); //npm i helmet  https://helmetjs.github.io/
const mongoSanitize = require('express-mongo-sanitize'); //npm i express-mongo-sanitize
const xss = require('xss-clean'); // npm i xss-clean
const hpp = require('hpp'); //against http parameter pollution -npm i hpp

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');

const app = express();

/**********MIDDLEWARES***********/

// 1) GLOBAL MIDDLEWARES
// Set security HTTP headers
app.use(helmet());


// Development logging
/*console.log(process.env.NODE_DEV); */
//make sure the logging happened only when we are on dev env
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev')); //npm pack that monitor req on terminal
  /*middleware stands between req ans res */
}

// Limit requests from same API (against brute force attacks like try to guess user password and send many get req)
//allow 100 per hour
const limiter = rateLimit({
  max: 3,
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour!'
});
app.use('/api', limiter); //use postman to check any get req header and see that after each req the Ratelimit change

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' })); //limit the req body to less than 10kb

// Data sanitization against NoSQL query injection - npm i express-mongo-sanitize
//if not exists let you login and get access to any account using the password the attacker put in the get req to see this:
//cancel this line,open postman on login req and enter in the body {"email":{"$gt":""}, "password": "pass1234"}
app.use(mongoSanitize());

// Data sanitization against XSS -cross side scripting attacks (adding malicious js code into html and inject it to uor site)
app.use(xss());

// Prevent parameter pollution
//using by sorting twice using the same param in the url req
//just like that: GET {{URL}}api/v1/tours?sort=duration&sort=price
//This list specify which properties we allow to be duplicates in the query string
app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingsQuantity',
      'ratingsAverage',
      'maxGroupSize',
      'difficulty',
      'price'
    ]
  })
);

// Serving static files
app.use(express.static(`${__dirname}/public`)); //in order to get access to statice file in the public dir

// Test middleware
app.use((req, res, next) => {
  //toISOString-format of date
  req.requestTime = new Date().toISOString();
  console.log(req.headers);
  next();
});

// 3) ROUTES
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
