"use strict";
Object.defineProperty(exports, "__esModule", { value: true });

const models = require("../models/index");
const basket_1 = require("../models/basket");
const user_1 = require("../models/user");
const challengeUtils = require("../lib/challengeUtils");
const config_1 = require("config");
const datacache_1 = require("../data/datacache");
const utils = require("../lib/utils");
const security = require('../lib/insecurity');
const winston = require('winston');

// Connect directly to our security logger
const logger = winston.createLogger({
    transports: [
        new winston.transports.File({ filename: 'security.log' })
    ]
});

module.exports = function login() {
    return (req, res, next) => {
        const email = req.body.email || '';

        models.sequelize.query('SELECT * FROM Users WHERE email = ? AND deletedAt IS NULL', 
            { replacements: [email], model: user_1.UserModel, plain: true })
            .then(async (authenticatedUser) => {
                const user = utils.queryResultToJson(authenticatedUser);

                if (user.data && user.data.password && req.body.password === user.data.password) {
                    // Success Path
                    basket_1.BasketModel.findOrCreate({ where: { UserId: user.data.id } })
                        .then(([basket]) => {
                            const token = security.authorize(user);
                            res.json({ authentication: { token, bid: basket.id, umail: user.data.email } });
                        });
                } else {
                    /* --- WEEK 4: INTRUSION DETECTION TRIGGER --- */
                    logger.warn(`SECURITY ALERT: Failed login attempt on account: ${email} from IP: ${req.ip}`);
                    res.status(401).send('Invalid email or password.');
                }
            }).catch((error) => {
                next(error);
            });
    };
};
