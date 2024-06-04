'use strict';

require('dotenv').config();

const config = {
    port: process.env.PORT || 3000,
    sessionKey: 'Authorization',
    blockingTime: 2 * 60 * 1000,
    timeRangeToCheck: 5000,
    domain: process.env.DOMAIN,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    audience: process.env.AUDIENCE,
}

module.exports = {
    config
}
