const express = require('express');
const connectDB = require('./config/db');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const videoController = require('./controllers/videoController');

// Initialize Express app
const app = express();
app.use(cors());
app.use(express.json());

// Load environment variables
require('dotenv').config();

// Connect to the database
connectDB();

// Define routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/room', require('./routes/roomRoutes'));
app.use('/api/video', require('./routes/videoRoutes'));

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.io on the HTTP server
const io = new Server(server, {
    cors: { origin: '*' }  // Allow cross-origin requests from any origin
});

// Socket.io connection handling
io.on('connection', (socket) => {
    console.log('A user connected');

    // Join a room
    socket.on('joinRoom', ({ roomId, userId }) => {
        socket.join(roomId);
        console.log(`User ${userId} joined room ${roomId}`);
        io.to(roomId).emit('message', `${userId} has joined the room`);
    });

    // Handle incoming messages and broadcast them
    socket.on('sendMessage', ({ roomId, userId, message }) => {
        io.to(roomId).emit('message', { userId, message });
    });

    // Handle video control (play/pause) and broadcast to the room
    socket.on('video-control', ({ roomId, action }) => {
        io.to(roomId).emit('video-control', action);
    });


    // Handle video control actions
    videoController.handleVideoControl(socket, io);

      // Handle a new video request and broadcast the video link
      socket.on('new-video', ({ roomId, videoLink }) => {
        console.log(`New video link: ${videoLink} in room ${roomId}`);
        io.to(roomId).emit('new-video', videoLink);
    });

    // Handle user disconnection
    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

// Start the server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
