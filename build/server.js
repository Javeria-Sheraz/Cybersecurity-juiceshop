"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.close = exports.start = void 0;

/* --- WEEK 3: SECURITY LOGGING --- */
const winston = require('winston'); 
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

/* Original Dependencies */
const fs = require("fs");
const path = require("path");
const models_1 = require("./models");
const config_1 = require("config");
const safe_1 = require("colors/safe");
const express = require('express');
const compression = require('compression');

/* --- WEEK 4 DEPENDENCIES --- */
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

/* Route Imports */
const login = require('./routes/login');
const utils = require("./lib/utils");

const app = express();

/* --- WEEK 4: API RATE LIMITING --- */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  message: "Too many requests from this IP, please try again later."
});
app.use('/rest/user/login', limiter); 

/* --- WEEK 4: API KEY GATEKEEPER AUTOMATION --- */
app.use('/api', (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    logger.warn(`UNAUTHORIZED API ACCESS ATTEMPTED: Missing API Key from IP ${req.ip}`);
    return res.status(403).json({ error: "X-API-KEY header missing." });
  }
  next();
});

/* --- WEEK 4: SECURITY HEADERS (CSP & HSTS WITH UI FIX) --- */
app.use(helmet({
  contentSecurityPolicy: false, 
  hsts: {
    maxAge: 31536000, 
    includeSubDomains: true,
    preload: true
  },
  crossOriginResourcePolicy: false,
  crossOriginEmbedderPolicy: false
}));

/* Middleware Configuration */
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* --- WEEK 5: CSRF PROTECTION LAYER --- */
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });
app.use((req, res, next) => {
  if (req.path === '/rest/user/login' || req.path.startsWith('/api')) {
    return next(); 
  }
  csrfProtection(req, res, next);
});

/* Serve Frontend Assets */
app.use(express.static(path.resolve('frontend/dist/frontend')));

/* Secure Login Route */
app.use('/rest/user/login', login());

/* --- LOG STARTUP EVENT --- */
logger.info('Application started: All security guidelines for Weeks 4-6 are active.');

exports.start = async () => {
    try {
        await models_1.sequelize.sync({ force: true }); 
        const datacreatorModule = require('./data/datacreator');
        const datacreator = typeof datacreatorModule === 'function' ? datacreatorModule : datacreatorModule.default;
        if (typeof datacreator === 'function') {
            await datacreator().catch(err => console.log("Non-critical insert error: " + err)); 
        }
        
        server.listen(3000, () => {
            console.log('Server listening on port 3000');
        });
    } catch (err) {
        logger.error('Failed to start server: ' + err);
    }
};

const server = require('http').Server(app);

exports.close = async () => {
    if (server) {
        server.close();
    }
};
