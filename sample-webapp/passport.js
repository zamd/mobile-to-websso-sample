const Iron = require('@hapi/iron');
const jwtDecode = require('jwt-decode');
const debug = require('debug')(process.env.APP_NAME);

const Auth0Startegy = require('passport-auth0'),
    passport = require('passport'),
    CustomStrategy = require('passport-custom');

const refreshTokens = require('./refreshTokens');

const auth0 = new Auth0Startegy({
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    scope: "openid email profile offline_access",
    passReqToCallback: true

}, (req, accessToken, refreshToken, _, profile, done) => {
    debug("Auth0 login successful, profile: %o", profile);
    req.session.a0Tokens = { accessToken, refreshToken };
    done(null, profile._json);
});

//store full user in memory.
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(auth0);
passport.use("mobileSessionAuth", new CustomStrategy(async function (req, done) {
    debug("Starting mobile session authentication.");
    if (req.cookies && req.cookies[process.env.MOBILE_SESSION_KEY]) {

        const sealed = req.cookies[process.env.MOBILE_SESSION_KEY];
        const password = process.env.CLIENT_SECRET;
        try {
            const mobileSession = await Iron.unseal(sealed, password, Iron.defaults);
            debug("Unsealed mobile session: %o", mobileSession);
            // Trigger push notification to mobile app via Auth0 Guardian (grant_type=refresh_token). 
            const a0Tokens = await refreshTokens(mobileSession.refresh_token);
            
            debug("Token refreshed succesfully - creating user.");
            //decode is sufficient here as tokens are acquired via backchannel over TLS. 
            const user = jwtDecode(a0Tokens.id_token);
            
            debug("Starting session for user: %o", user);
            return done(null, user);
        }catch(err) {
            debug("mobileSessionAuth failed: %O",err);
            return done(err, null);
        }
    }
    debug("Mobile session cookie missing, skipping auth...");
    return done(null, null);
}));

module.exports = function setupPassport(app) {
    app.use(passport.initialize());
    app.use(passport.session());
}
