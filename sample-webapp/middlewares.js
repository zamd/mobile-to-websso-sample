const debug = require('debug')(process.env.APP_NAME);
const Iron = require('@hapi/iron');

function saveState(req, res, next) {
    debug("Saving continue state, query: %o",req.query);
    if (req.query && req.query.state) {
        req.session['continueState'] = req.query.state;
    }
    next();
}

function auth0Continue(req, res) {
    debug("Continuing after login. user: %o",req.user);
    const continueUrl = `https://${process.env.AUTH0_DOMAIN}/continue?state=${req.session.continueState}`;
    res.redirect(continueUrl);
}


async function createMobileSession(req, res, next) {
    debug("Continuing mobile session for: %o",req.user);
    if (!req.session || !req.session.a0Tokens)
        return next("Required session data missing.");

    const mobile_session = {
        refresh_token: req.session.a0Tokens.refreshToken,
        session_permissions: [
            "perm1",
            "perm-2"
        ]
    };
    const password = process.env.CLIENT_SECRET;
    const sealed = await Iron.seal(mobile_session, password, Iron.defaults);

    const oneYear = 86400 * 30 * 12 * 1000;
    //WARN: Secure:false for testing only. The flag must be set to "true" when moved to HTTPS
    res.cookie(process.env.MOBILE_SESSION_KEY, sealed, { httpOnly: true, maxAge: oneYear, sameSite: "lax" })
    debug("Cookie sent: %s=%s",process.env.MOBILE_SESSION_KEY, sealed);
    next();
}







module.exports = { saveState, auth0Continue, createMobileSession };