const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.register = async (req, res) => {
    const { username, email, password, role } = req.body;

    console.log('Incoming registration request:', req.body); // Log incoming request

    try {
        // Check if the user already exists
        let user = await User.findOne({ email });
        if (user) {
            console.error('User already exists:', email); // Log if user exists
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Create a new user instance
        user = new User({ username, email, password, role });

        // Hash the password before saving
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // Attempt to save the user to the database
        await user.save();

        // Create JWT payload
        const payload = {
            user: { id: user.id, role: user.role },
        };

        // Attempt to sign the JWT token
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) {
                console.error('JWT signing error:', err.message); // Log JWT errors
                return res.status(500).json({ msg: 'Token generation failed' });
            }
            // Return the token on successful registration
            res.status(200).json({ token });
        });

    } catch (err) {
        // Log the entire error object for detailed insights
        console.error('Error during registration:', err); 
        res.status(500).json({ msg: 'Server error' });
    }
};



exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

        const payload = {
            user: { id: user.id, role: user.role }
        };

        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, payload });
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};
