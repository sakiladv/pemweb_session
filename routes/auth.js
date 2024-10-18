const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../config/db');

// Render registration page
router.get('/register', (req, res) => {
    res.render('register');
});

// Process user registration
router.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    const query = "INSERT INTO userrs (username, email, password) VALUES (?, ?, ?)";
    db.query(query, [username, email, hashedPassword], (err, result) => {
        if (err) throw err;
        res.redirect('/auth/login');
    });
});

// Render login page
router.get('/login', (req, res) => {
    res.render('login');
});

// Process user login
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = "SELECT * FROM userrs WHERE username = ?";
    db.query(query, [username], (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
            const user = result[0];

            if (bcrypt.compareSync(password, user.password)) {
                req.session.user = user;
                res.redirect('/auth/profile');
            } else {
                res.send('Incorrect password');
            }
        } else {
            res.send('User not found');
        }
    });
});

// Render user profile page
router.get('/profile', (req, res) => {
    if (req.session.user) {
        res.render('profile', { user: req.session.user });
    } else {
        res.redirect('/auth/login');
    }
});

// Process logout
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/auth/login');
});

module.exports = router;
