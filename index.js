const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const {logger} = require("./logger.js");
const {config} = require("./config");
const { checkIfBlocked } = require('./utils/history');
const { saveUnsuccessfulAttempt } = require('./utils/history');
const { registerUser } = require('./utils/user');
const { getUserDetailedInformation } = require('./utils/user');
const { refreshAccessToken } = require('./utils/auth');
const { authUserByLoginAndPassword } = require('./utils/auth');
const { getAccessToken } = require('./utils/auth');

const userInfo = {}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

function retrieveToken(request) {
    const headerValue = request.get(config.sessionKey);
    if (headerValue) {
        token = headerValue.split(" ")[1];
        if (token) {
            return token;
        }
    }
    return null;
}

function checkTokenAndGetUserId(token) {
    const payload = jwt.decode(token);
    const userId = payload.sub;
    if (userInfo[userId] !== undefined && userInfo[userId].accessToken === token) {
        return payload;
    }
    return null;
}

app.use(async (req, res, next) => {
    let token = retrieveToken(req);
    if (token) {
        const payload = checkTokenAndGetUserId(token);
        if (payload) {
            const userId = payload.sub;
            const tokenValidTime = userInfo[payload.sub].expiresIn - 4 * 60 * 60 * 1000;
            if (Date.now() >= tokenValidTime) {
                token = await refreshAccessToken(userId, userInfo);
            }
            req.token = token
            req.userId = userId;
        }
    }
    next();
});

app.get('/', (req, res) => {
    const {token} = req;
    if (token) {
        const {userId} = req;
        return res.json({
            token: token,
            username: userInfo[userId].name
        });
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    delete userInfo[req.userId];
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;
    const authInfo = await authUserByLoginAndPassword(login, password);
    const ip = req.socket.remoteAddress;
    if (authInfo.accessToken !== undefined && !checkIfBlocked(ip)) {
        logger.info(`Successfully logged in, IP: ${ip}, user: ${login}`);
        const payload = jwt.decode(authInfo.accessToken);
        const userId = payload.sub;
        const userDetailedInfo = await getUserDetailedInformation(userId, authInfo.accessToken);
        userDetailedInfo.refreshToken = authInfo.refreshToken;
        userDetailedInfo.accessToken = authInfo.accessToken;
        userDetailedInfo.expiresIn = Date.now() + authInfo.expiresIn * 1000;
        userInfo[userId] = userDetailedInfo;
        return res.json({
            token: authInfo.accessToken
        });
    } else {
        saveUnsuccessfulAttempt(ip);
        logger.info(`Unsuccessful attempt to login from IP: ${ip}`);
    }
    return res.status(401).send();
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname + '/signup.html'));
});

app.post('/api/signup', async (req, res) => {
    const {login, password, name, nickname} = req.body;
    const clientAccessToken = await getAccessToken();
    const result = await registerUser(clientAccessToken, login, password, name, nickname);
    if (result) {
        logger.info(`Successfully registered user with login ${login}`);
        return res.json({redirect: '/'});
    }
    return res.status(500).send();
});


app.listen(config.port, () => {
    logger.info(`Example app listening on port ${config.port}`);
});
