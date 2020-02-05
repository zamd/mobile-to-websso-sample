const Iron = require('@hapi/iron');

function saveState(req, res, next) {
    if (req.query && req.query.state) {
        req.session['continueState'] = req.query.state;
    }
    next();
}

function auth0Continue(req, res) {
    const continueUrl = `https://${process.env.AUTH0_DOMAIN}/continue?state=${req.session.continueState}`;
    res.redirect(continueUrl);
}


async function createMobileSession(req, res, next) {
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

    next();
}







module.exports = { saveState, auth0Continue, createMobileSession };