require('dotenv').config()
const defaultEnv = require('./env');

process.env = {
    ...process.env,
    ...defaultEnv
};

const express = require('express');
const path = require('path');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const { ensureLoggedIn } = require('connect-ensure-login');

const setupPassport = require('./passport');


const { saveState, auth0Continue, createMobileSession } = require('./middlewares');

const indexRouter = require('./routes/index');


var app = express();
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: "sid",
    cookie: {
        maxAge: 3600000,
        //secure:true,
        httpOnly: true,
        sameSite: "lax" //required for code flow.
    }
}));

setupPassport(app);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use('/login/callback', passport.authenticate("auth0"), createMobileSession, auth0Continue);
app.use('/login', saveState, passport.authenticate("auth0"));

app.use('/mobile', passport.authenticate('mobileSessionAuth'), (_, res) => res.redirect('/'));

app.use(ensureLoggedIn('/login'));

app.use('/', indexRouter);


// catch 404 and forward to error handler
app.use(function (req, res, next) {
    next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
    const sanitize = err => err.isBoom ? {...err.output.payload, status: err.output.statusCode} : err;

    err = sanitize(err);
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.render('error');
});

module.exports = app;