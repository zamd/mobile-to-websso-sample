const Iron = require('@hapi/iron');

const Auth0Startegy = require('passport-auth0'),
    passport = require('passport'),
    CustomStrategy = require('passport-custom');


const auth0 = new Auth0Startegy({
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    scope: "openid email profile offline_access",
    passReqToCallback: true

}, (req, accessToken, refreshToken, _, profile, done) => {
    req.session.a0Tokens = { accessToken, refreshToken };
    done(null, profile._json);
});

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(auth0);
passport.use("mobileSessionAuth", new CustomStrategy(async function (req, done) {
    if (req.cookies && req.cookies[process.env.MOBILE_SESSION_KEY]) {

        const sealed = req.cookies[process.env.MOBILE_SESSION_KEY];
        const password = process.env.CLIENT_SECRET;
        try {
            const mobileSession = await Iron.unseal(sealed, password, Iron.defaults);
            // Trigger push notification to mobile app via Auth0 Guardian (grant_type=refresh_token). 
            // Todo: check amr claim before issuing session. 
            const user = await refreshTokens(req, mobileSession.refreshToken);

            return done(null, user);
        }catch(err) {
            return done(err, null);
        }
    }

    return done(null, null);
}));


async function refreshTokens(req, rt) {
    //TODO: refresh_token grant.
    console.log("todo: refresh_token grant...");
    await req.user;
}


module.exports = function setupPassport(app) {
    app.use(passport.initialize());
    app.use(passport.session());
}
