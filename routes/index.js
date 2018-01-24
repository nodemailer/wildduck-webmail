'use strict';

const config = require('wild-config');
const express = require('express');
const router = new express.Router();

/* GET home page. */
router.get('/', (req, res) => {
    res.render('index', {});
});

router.get('/help', (req, res) => {
    res.render('help', {
        activeHelp: true,
        setup: config.setup
    });
});

router.get('/tos', (req, res) => {
    res.render('tos', {
        activeCreate: true
    });
});

module.exports = router;
