const Room = require('../models/Room');

exports.addVideoLink = async (req, res) => {
    const { roomId, link } = req.body;

    // Validate video link (example validation, this should be more comprehensive)
    if (!link || !isValidUrl(link)) {
        return res.status(400).json({ msg: 'Invalid video link' });
    }

    try {
        const room = await Room.findById(roomId);
        if (!room) return res.status(404).json({ msg: 'Room not found' });

        // Only the room owner can add the video link
        if (room.owner.toString() !== req.user.id) {
            return res.status(403).json({ msg: 'Only the room owner can add the video link' });
        }

        // Update room with the new video link
        room.videoLink = link;
        await room.save();

        // Emit the new video link to all users in the room
        const io = req.app.get('io');
        io.to(roomId).emit('new-video', link);

        res.json(room);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// Handle video control actions (play, pause, etc.)
exports.handleVideoControl = (socket, io) => {
    socket.on('video-control', ({ roomId, action }) => {
        io.to(roomId).emit('video-control', action); // Broadcast action to all clients in the room
    });
};

// Utility function to validate URLs (example implementation)
const isValidUrl = (urlString) => {
    try {
        new URL(urlString);
        return true;
    } catch (e) {
        return false;
    }
};
