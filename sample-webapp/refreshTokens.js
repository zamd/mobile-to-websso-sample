const debug = require('debug')(process.env.APP_NAME);
const rp = require('request-promise');
const Boom = require('boom');

async function refreshTokens(refreshToken) {
    const options = {
        uri: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
        method: "POST",
        json: {
            grant_type: "refresh_token",
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            refresh_token: refreshToken
        }
    };

    debug("Starting refresh_token grant %o",options);
    return rp(options)
    .catch(handleMFARequired);
}

async function handleMFARequired(res) {
    if (res.statusCode!==403 && res.error.mfa_token) {
        debug("refresh_token grant failed with unexpected error %O",res);
        throw res;
    }
    const mfaToken = res.error.mfa_token;
    const oobCode = await mfaChallenge(mfaToken);
    return await waitForAuthorization(mfaToken, oobCode);
}


async function mfaChallenge(mfaToken) {
    const options = {
        uri: `https://${process.env.AUTH0_DOMAIN}/mfa/challenge`,
        method: "POST",
        json: {
            challenge_type: "oob",
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            mfa_token: mfaToken
        }
    };

    debug("Starting MFA challenge: %o",options);
    const res = await rp(options);
    return res.oob_code;
}


async function waitForAuthorization(mfaToken, oobCode) {
    const TIMEOUT = 30*1000;
    const RETRY_INTERVAL = 5*1000;

    const options = {
        uri: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
        method: "POST",
        json: {
            grant_type: "http://auth0.com/oauth/grant-type/mfa-oob",
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            mfa_token: mfaToken,
            oob_code: oobCode
        }
    };
    
    debug("Checking MFA approval: %o",options);

    return new Promise((resolve, reject) => {
        const timeoutTimer = setTimeout(timeout , TIMEOUT);
        const retryTimer = setInterval(checkAuthorization, RETRY_INTERVAL);
        let attempt = 0;

        function clearTimers() {
            clearTimeout(timeoutTimer);
            clearTimeout(retryTimer);
        }

        function timeout() {
            debug("MFA Approval timed-out after %d seconds", TIMEOUT/1000);
            clearTimers();
            reject(Boom.unauthorized("MFA authorization/response timeout."));
        }

        function checkAuthorization() {
            debug("Checking authorization: attempt %d",++attempt);
            rp(options)
            .then(r=>{
                debug("MFA approved.");
                clearTimers();
                resolve(r);
            })
            .catch(err => {
                if (err.statusCode!==400 ||
                    err.error.error!=="authorization_pending") { //authorization_pending is expected error
                        debug("Approval check failed. Error: %O",err);
                        clearTimers();
                        reject(err);
                }
            });
        }
    });
}


module.exports = refreshTokens;