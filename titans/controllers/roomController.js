const Room = require('../models/Room');
const User = require('../models/User');

exports.createRoom = async (req, res) => {
    const { name } = req.body;
    try {
        const room = new Room({ name, owner: req.user.id });
        await room.save();
       
        res.json({ roomId: room._id, room });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// controllers/roomController.js
 // Adjust the path as necessary

exports.getRoom = async (req, res) => {
    const { roomId } = req.params;
    try {
        const room = await Room.findById(roomId);
        if (!room) {
            return res.status(404).json({ msg: 'Room not found' });
        }
        console.log(room.participants);
        res.json(room);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// Existing createRoom and joinRoom functions


exports.joinRoom = async (req, res) => {
    const { roomId } = req.body;
    try {
        const room = await Room.findById(roomId);
        if (!room) return res.status(404).json({ msg: 'Room not found' });

        room.participants.push(req.user.id);
        await room.save();
        res.json(room);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// controllers/roomController.js

exports.endRoom = async (req, res) => {
    const { roomId } = req.body;
    try {
        const room = await Room.findById(roomId);
        if (!room) return res.status(404).json({ msg: 'Room not found' });

        if (room.owner.toString() !== req.user.id) {
            return res.status(403).json({ msg: 'Only the room owner can end the room' });
        }

        // Remove the room
        await Room.findByIdAndDelete(roomId);

        // Optionally notify all users
        req.app.get('io').to(roomId).emit('room-ended');

        res.json({ msg: 'Room ended successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

