"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });

const models = require("../models/index");
const basket_1 = require("../models/basket");
const user_1 = require("../models/user");
const challengeUtils = require("../lib/challengeUtils");
const config_1 = __importDefault(require("config"));
const datacache_1 = require("../data/datacache");
const utils = __importStar(require("../lib/utils"));
const security = require('../lib/insecurity');
const users = require('../data/datacache').users;
const validator = require('validator');
const bcrypt = require('bcrypt');

module.exports = function login() {
    function afterLogin(user, res, next) {
        verifyPostLoginChallenges(user);
        basket_1.BasketModel.findOrCreate({ where: { UserId: user.data.id } })
            .then(([basket]) => {
                const token = security.authorize(user);
                user.bid = basket.id;
                security.authenticatedUsers.put(token, user);
                res.json({ authentication: { token, bid: basket.id, umail: user.data.email } });
            }).catch((error) => {
                next(error);
            });
    }

    return (req, res, next) => {
        verifyPreLoginChallenges(req);

        // --- LAYER 1: INPUT VALIDATION & SANITIZATION ---
        const email = req.body.email || '';
        if (!validator.isEmail(email) || email.includes("'") || email.includes("--")) {
            return res.status(401).send("Unauthorized: Malicious characters or invalid email detected.");
        }

        // --- LAYER 2: PARAMETERIZED QUERY (REPLACEMENTS) ---
        models.sequelize.query('SELECT * FROM Users WHERE email = ? AND deletedAt IS NULL', 
            { replacements: [email], model: user_1.UserModel, plain: true })
            .then(async (authenticatedUser) => {
                const user = utils.queryResultToJson(authenticatedUser);

                // --- LAYER 3: BCRYPT PASSWORD VERIFICATION ---
                let isValid = false;
                if (user.data && user.data.password) {
                    isValid = await bcrypt.compare(req.body.password || '', user.data.password);
                }

                if (isValid && user.data?.id) {
                    // Check for Two-Factor Authentication (TOTP)
                    if (user.data.totpSecret !== '') {
                        res.status(401).json({
                            status: 'totp_token_required',
                            data: {
                                tmpToken: security.authorize({
                                    userId: user.data.id,
                                    type: 'password_valid_needs_second_factor_token'
                                })
                            }
                        });
                    } else {
                        afterLogin(user, res, next);
                    }
                } else {
                    // Standard Juice Shop UI error message
                    res.status(401).send(res.__('Invalid email or password.'));
                }
            }).catch((error) => {
                next(error);
            });
    };

    function verifyPreLoginChallenges(req) {
        challengeUtils.solveIf(datacache_1.challenges.weakPasswordChallenge, () => { return req.body.email === 'admin@' + config_1.default.get('application.domain') && req.body.password === 'admin123'; });
    }

    function verifyPostLoginChallenges(user) {
        challengeUtils.solveIf(datacache_1.challenges.loginAdminChallenge, () => { return user.data.id === users.admin.id; });
        challengeUtils.solveIf(datacache_1.challenges.loginJimChallenge, () => { return user.data.id === users.jim.id; });
        challengeUtils.solveIf(datacache_1.challenges.loginBenderChallenge, () => { return user.data.id === users.bender.id; });
    }
};
