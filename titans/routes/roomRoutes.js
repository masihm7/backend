// routes/roomRoutes.js

const express = require('express');
const { createRoom, getRoom, joinRoom, endRoom } = require('../controllers/roomController');
const authMiddleware = require('../middlewares/authMiddleware');
const roleMiddleware = require('../middlewares/roleMiddleware');
const router = express.Router();

// Route to create a room
router.post('/create', authMiddleware, roleMiddleware(['organizer', 'admin']), createRoom);

// Route to get room details by roomId
router.get('/:roomId', authMiddleware, getRoom); // Ensure authMiddleware is used for authentication

// Route to join a room
router.post('/join', authMiddleware, joinRoom);

// Route to end a room
router.post('/end', authMiddleware, roleMiddleware(['admin']), endRoom); // Only admins can end a room

module.exports = router;
