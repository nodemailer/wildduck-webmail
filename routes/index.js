'use strict';

const config = require('wild-config');
const express = require('express');
const router = new express.Router();

/* GET home page. */
router.get('/', (req, res) => {
    res.render('index', {});
});

/* GET home page. */
router.get('/help', (req, res) => {
    res.render('help', {
        activeHelp: true,
        setup: config.setup
    });
});

module.exports = router;
