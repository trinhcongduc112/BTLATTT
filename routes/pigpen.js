const express = require('express');
const router = express.Router();
const pigpen = require('../ciphers/pigpen');

router.post('/encrypt', async (req, res) => {
    try {
        const { text } = req.body;
        const ciphertext = pigpen.encrypt(text);
        res.json({ ciphertext });
    } catch (error) {
        console.error('Error in pigpen encrypt:', error);
        res.status(error.message.includes('required') || error.message.includes('long') ? 400 : 500)
           .json({ error: error.message });
    }
});

router.post('/decrypt', async (req, res) => {
    try {
        const { text } = req.body;
        const plaintext = pigpen.decrypt(text);
        res.json({ plaintext });
    } catch (error) {
        console.error('Error in pigpen decrypt:', error);
        res.status(error.message.includes('required') || error.message.includes('long') ? 400 : 500)
           .json({ error: error.message });
    }
});

module.exports = router; 