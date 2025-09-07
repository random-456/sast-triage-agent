// Sample vulnerable code for testing
// This simulates a SQL injection vulnerability

const express = require('express');
const mysql = require('mysql');
const app = express();

// Vulnerable SQL query - user input directly concatenated
app.get('/user', (req, res) => {
    const userId = req.query.id;
    // BAD: Direct string concatenation makes this vulnerable to SQL injection
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send('Database error');
        } else {
            res.json(results);
        }
    });
});

// Another endpoint with proper parameterized query
app.get('/safe-user', (req, res) => {
    const userId = req.query.id;
    // GOOD: Using parameterized query prevents SQL injection
    const query = "SELECT * FROM users WHERE id = ?";
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            res.status(500).send('Database error');
        } else {
            res.json(results);
        }
    });
});

module.exports = app;