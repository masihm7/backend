const express = require('express');
const { addVideoLink } = require('../controllers/videoController');
const authMiddleware = require('../middlewares/authMiddleware');
const roleMiddleware = require('../middlewares/roleMiddleware');
const router = express.Router();

router.post('/link', authMiddleware, roleMiddleware(['organizer', 'admin']), addVideoLink);

module.exports = router;
