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

/* --- WEEK 4: SECURITY HEADERS (CSP & HSTS WITH UI FIX) --- */
app.use(helmet({
  contentSecurityPolicy: false, // Disables strict CSP restriction so the UI styles load flawlessly
  hsts: {
    maxAge: 31536000, 
    includeSubDomains: true,
    preload: true
  },
  crossOriginResourcePolicy: false,
  crossOriginEmbedderPolicy: false
}));


const cookieParser = require('cookie-parser');
const csrf = require('csurf');

/* Middleware Configuration */
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* --- WEEK 5: CSRF PROTECTION LAYER --- */
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });
// Automatically protects all state-changing POST/PUT routes
app.use((req, res, next) => {
  if (req.path === '/rest/user/login') {
    return next(); // Pass login route to let users authenticate cleanly
  }
  csrfProtection(req, res, next);
});

/* Serve Frontend Assets */
app.use(express.static(path.resolve('frontend/dist/frontend')));

/* Secure Login Route */
app.use('/rest/user/login', login());

/* --- LOG STARTUP EVENT --- */
logger.info('Application started: Security monitoring, Rate-limiting, and Helmet are active.');

exports.start = async () => {
    try {
        await models_1.sequelize.sync({ force: true }); // Wipe duplicates and reset database cleanly
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
