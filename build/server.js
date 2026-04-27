"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.close = exports.start = void 0;

/* --- WEEK 3: SECURITY LOGGING [cite: 50, 51] --- */
const winston = require('winston'); 
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

/* Original Dependencies */
const fs = require("fs");
const path_1 = require("path");
const models_1 = require("./models");
const config_1 = require("config");
const safe_1 = require("colors/safe");
const express = require('express');
const compression = require('compression');

/* --- WEEK 2: SECURE DATA TRANSMISSION [cite: 42, 44] --- */
const helmet = require('helmet');

/* Route Imports */
const login = require('./routes/login');
const utils = require("./lib/utils");

const app = express();

/* --- ACTIVATE HELMET (Relaxed for UI) [cite: 46] --- */
app.use(
  helmet({
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false,
  })
);

const server = require('http').Server(app);

/* Sets view engine */
app.set('view engine', 'hbs');

/* Middleware & Routes */
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* Serve Frontend Assets (Fixes the "Ruined" look) */
app.use(express.static(path_1.resolve('frontend/dist/frontend')));

/* The Secure Login Route we patched */
app.use('/rest/user/login', login());

/* --- LOG STARTUP EVENT  --- */
logger.info('Application started: Security monitoring and Helmet protection are active.');

exports.start = async () => {
    try {
        await models_1.sequelize.sync();
        server.listen(3000, () => {
            console.log('Server listening on port 3000');
        });
    } catch (err) {
        logger.error('Failed to start server: ' + err);
    }
};

exports.close = async () => {
    if (server) {
        server.close();
    }
};
