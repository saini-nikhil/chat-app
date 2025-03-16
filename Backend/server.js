const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'Server is running!' });
});

// MongoDB Connection
const MONGO_URI = 'mongodb://localhost:27017/chatapp';

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, default: 'offline' }, // online, offline
  accessibleRooms: [{ type: String }] // Rooms the user has access to
});

const MessageSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  sender: { type: String, required: true },
  room: { type: String, required: true },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  status: { type: String, default: 'sent' }, // sent, delivered, seen
  seenBy: [{ type: String }]
});

const RoomSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  creator: {
    type: String,
    required: true
  },
  isPrivate: {
    type: Boolean,
    default: false
  },
  users: {
    type: [String],
    default: []
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const RoomRequestSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  roomName: { type: String, required: true },
  status: { type: String, default: 'pending' }, // pending, approved, rejected
  createdAt: { type: Date, default: Date.now }
});

const RoomInvitationSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  inviter: { type: String, required: true },
  invitee: { type: String, required: true },
  roomName: { type: String, required: true },
  status: { type: String, default: 'pending' }, // pending, accepted, declined
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);
const Room = mongoose.model('Room', RoomSchema);
const RoomRequest = mongoose.model('RoomRequest', RoomRequestSchema);
const RoomInvitation = mongoose.model('RoomInvitation', RoomInvitationSchema);

// Create default room if it doesn't exist
async function ensureDefaultRoomExists() {
  try {
    const defaultRoom = await Room.findOne({ name: 'general' });
    
    if (!defaultRoom) {
      console.log('Creating default room: general');
      
      const room = new Room({
        name: 'general',
        creator: 'system',
        isPrivate: false,
        users: []
      });
      
      await room.save();
      console.log('Default room created');
    } else {
      console.log('Default room already exists');
    }
  } catch (error) {
    console.error('Error ensuring default room exists:', error);
  }
}

// Authentication Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user with access to default rooms
    const newUser = new User({
      username,
      password: hashedPassword,
      status: 'offline',
      accessibleRooms: ['general', 'tech', 'random']
    });
    
    await newUser.save();
    
    // Create token
    const token = jwt.sign({ id: newUser._id }, 'your_jwt_secret', {
      expiresIn: '1d',
    });
    
    res.status(201).json({ token, username });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Create token
    const token = jwt.sign({ id: user._id }, 'your_jwt_secret', {
      expiresIn: '1d',
    });
    
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Message and Room Routes
app.get('/api/messages/:room', async (req, res) => {
  try {
    console.log(`Fetching messages for room ${req.params.room}`);
    
    // Find messages for this room
    const messages = await Message.find({ room: req.params.room })
      .sort({ timestamp: 1 })
      .limit(100); // Limit to last 100 messages
    
    console.log(`Found ${messages.length} messages for room ${req.params.room}`);
    
    res.json(messages);
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/rooms', async (req, res) => {
  try {
    console.log('Fetching public rooms');
    
    // Find all public rooms
    const rooms = await Room.find({ isPrivate: false });
    
    // Extract room names
    const roomNames = rooms.map(room => room.name);
    
    console.log(`Found ${roomNames.length} public rooms`);
    res.json(roomNames);
  } catch (err) {
    console.error('Error fetching public rooms:', err);
    res.status(500).json({ message: err.message });
  }
});

// Get room access requests for a room creator
app.get('/api/room-requests/:username', async (req, res) => {
  try {
    console.log(`Fetching room access requests for ${req.params.username}`);
    
    // Find rooms created by this user
    const rooms = await Room.find({ creator: req.params.username });
    const roomNames = rooms.map(room => room.name);
    
    console.log(`Found ${roomNames.length} rooms created by ${req.params.username}`);
    
    // Find pending requests for these rooms
    const requests = await RoomRequest.find({
      roomName: { $in: roomNames },
      status: 'pending'
    });
    
    console.log(`Found ${requests.length} pending requests for rooms created by ${req.params.username}`);
    
    // Format requests for frontend
    const formattedRequests = requests.map(request => ({
      id: request.id,
      username: request.username,
      room: request.roomName
    }));
    
    res.json(formattedRequests);
  } catch (err) {
    console.error('Error fetching room access requests:', err);
    res.status(500).json({ message: err.message });
  }
});

// Get room invitations for a user
app.get('/api/room-invitations/:username', async (req, res) => {
  try {
    console.log(`Fetching room invitations for ${req.params.username}`);
    
    // Find all invitations for this user
    const invitations = await RoomInvitation.find({ 
      invitee: req.params.username,
      status: 'pending' // Only return pending invitations
    });
    
    console.log(`Found ${invitations.length} pending invitations for ${req.params.username}`);
    
    // Format invitations for frontend
    const formattedInvitations = invitations.map(invitation => ({
      id: invitation.id,
      room: invitation.roomName,
      from: invitation.inviter,
      status: invitation.status
    }));
    
    res.json(formattedInvitations);
  } catch (err) {
    console.error('Error fetching room invitations:', err);
    res.status(500).json({ message: err.message });
  }
});

// Get user's accessible rooms
app.get('/api/user-rooms/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user.accessibleRooms || []);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get rooms where user is a member
app.get('/api/rooms-with-user/:username', async (req, res) => {
  try {
    console.log(`Fetching rooms where ${req.params.username} is a member`);
    
    // Find rooms where user is in the users array
    const rooms = await Room.find({ users: req.params.username });
    
    // Extract room names
    const roomNames = rooms.map(room => room.name);
    
    console.log(`Found ${roomNames.length} rooms with ${req.params.username} as member`);
    res.json(roomNames);
  } catch (err) {
    console.error('Error fetching rooms with user:', err);
    res.status(500).json({ message: err.message });
  }
});

// Delete a room (only creator can delete)
app.delete('/api/rooms/:roomName', async (req, res) => {
  try {
    const { roomName } = req.params;
    const { username } = req.query;
    
    console.log(`Request to delete room ${roomName} by ${username}`);
    
    // Find the room
    const room = await Room.findOne({ name: roomName });
    
    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }
    
    // Check if user is the creator
    if (room.creator !== username) {
      return res.status(403).json({ message: 'Only the room creator can delete this room' });
    }
    
    // Delete all messages in the room
    await Message.deleteMany({ room: roomName });
    
    // Delete all invitations for this room
    await RoomInvitation.deleteMany({ roomName });
    
    // Delete all access requests for this room
    await RoomRequest.deleteMany({ roomName });
    
    // Remove room from users' accessible rooms
    await User.updateMany(
      { accessibleRooms: roomName },
      { $pull: { accessibleRooms: roomName } }
    );
    
    // Delete the room
    await Room.deleteOne({ name: roomName });
    
    console.log(`Room ${roomName} deleted by ${username}`);
    
    // Return success
    res.json({ message: 'Room deleted successfully' });
  } catch (err) {
    console.error('Error deleting room:', err);
    res.status(500).json({ message: err.message });
  }
});

// Get room details
app.get('/api/rooms/:roomName', async (req, res) => {
  try {
    console.log(`Fetching details for room ${req.params.roomName}`);
    
    // Find the room
    const room = await Room.findOne({ name: req.params.roomName });
    
    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }
    
    // Return room details
    res.json({
      name: room.name,
      creator: room.creator,
      isPrivate: room.isPrivate,
      users: room.users,
      createdAt: room.createdAt
    });
  } catch (err) {
    console.error('Error fetching room details:', err);
    res.status(500).json({ message: err.message });
  }
});

// Socket.io Connection
const connectedUsers = new Map();
const userSocketMap = new Map(); // Maps username to socketId
const typingUsers = new Map(); // Maps rooms to typing users
const roomAccessRequests = new Map(); // Maps requestId to request data
const roomInvitations = new Map(); // Maps invitationId to invitation data
const onlineUsers = {};

// Helper function to find a socket by username
function findSocketByUsername(username) {
  const socketId = userSocketMap.get(username);
  if (socketId) {
    return io.sockets.sockets.get(socketId);
  }
  return null;
}

io.on('connection', (socket) => {
  console.log('New client connected');
  
  // Join room
  socket.on('join', ({ username, room }) => {
    console.log(`${username} joined ${room}`);
    
    // Store the user's socket
    userSocketMap.set(username, socket.id);
    console.log(`Mapped ${username} to socket ${socket.id}`);
    
    // Add user to room
    socket.join(room);
    
    // Add user to online users for this room
    if (!onlineUsers[room]) {
      onlineUsers[room] = [];
    }
    
    if (!onlineUsers[room].includes(username)) {
      onlineUsers[room].push(username);
    }
    
    // Send welcome message
    socket.emit('message', {
      id: uuidv4(),
      sender: 'admin',
      text: `Welcome to ${room}, ${username}!`,
      timestamp: new Date(),
      status: 'delivered',
      seenBy: []
    });
    
    // Broadcast to others
    socket.broadcast.to(room).emit('message', {
      id: uuidv4(),
      sender: 'admin',
      text: `${username} has joined the chat`,
      timestamp: new Date(),
      status: 'delivered',
      seenBy: []
    });
    
    // Send room data
    io.to(room).emit('roomData', {
      room,
      users: onlineUsers[room]
    });
  });
  
  // Leave room
  socket.on('leave', ({ username, room }) => {
    console.log(`${username} left ${room}`);
    
    // Remove user from room
    socket.leave(room);
    
    // Remove user from online users for this room
    if (onlineUsers[room]) {
      onlineUsers[room] = onlineUsers[room].filter(user => user !== username);
    }
    
    // Send room data
    io.to(room).emit('roomData', {
      room,
      users: onlineUsers[room] || []
    });
  });
  
  // Send message
  socket.on('sendMessage', async ({ id, sender, room, text, timestamp }) => {
    try {
      console.log(`Message from ${sender} in ${room}: ${text}`);
      
      // Validate room exists
      const roomExists = await Room.findOne({ name: room });
      if (!roomExists) {
        console.error(`Room not found: ${room}`);
        socket.emit('error', { message: 'Room not found' });
        return;
      }
      
      // Check if user has access to the room
      const user = await User.findOne({ username: sender });
      if (!user) {
        console.error(`User not found: ${sender}`);
        socket.emit('error', { message: 'User not found' });
        return;
      }
      
      // For private rooms, check if user has access
      if (roomExists.isPrivate && !roomExists.users.includes(sender) && roomExists.creator !== sender) {
        console.error(`User ${sender} does not have access to room ${room}`);
        socket.emit('error', { message: 'You do not have access to this room' });
        return;
      }
      
      // Create message
      const message = new Message({
        id,
        sender,
        room,
        text,
        timestamp: timestamp || new Date(),
        status: 'delivered',
        seenBy: []
      });
      
      // Save message
      await message.save();
      
      // Send message to room
      io.to(room).emit('message', message);
    } catch (error) {
      console.error('Error sending message:', error);
      socket.emit('error', { message: 'Error sending message: ' + error.message });
    }
  });
  
  // Message seen
  socket.on('messageSeen', async ({ messageId, room, username }) => {
    try {
      // Find message
      const message = await Message.findOne({ id: messageId });
      
      if (message) {
        // Add user to seenBy if not already there
        if (!message.seenBy.includes(username)) {
          message.seenBy.push(username);
          message.status = 'seen';
          await message.save();
        }
        
        // Broadcast message update
        io.to(room).emit('messageUpdated', {
          messageId,
          status: message.status,
          seenBy: message.seenBy
        });
      }
    } catch (error) {
      console.error('Error marking message as seen:', error);
      socket.emit('error', { message: 'Error marking message as seen' });
    }
  });
  
  // Typing
  socket.on('typing', ({ username, room, isTyping }) => {
    // Initialize typing users for this room if not exists
    if (!typingUsers[room]) {
      typingUsers[room] = [];
    }
    
    if (isTyping) {
      // Add user to typing users if not already there
      if (!typingUsers[room].includes(username)) {
        typingUsers[room].push(username);
      }
    } else {
      // Remove user from typing users
      typingUsers[room] = typingUsers[room].filter(user => user !== username);
    }
    
    // Broadcast typing users
    socket.broadcast.to(room).emit('typing', {
      users: typingUsers[room]
    });
  });
  
  // Create room
  socket.on('createRoom', async ({ username, roomName, isPrivate }) => {
    try {
      console.log(`Creating room: ${roomName} by ${username}, isPrivate: ${isPrivate}`);
      
      // Check if room already exists
      const existingRoom = await Room.findOne({ name: roomName });
      
      if (existingRoom) {
        console.error(`Room ${roomName} already exists`);
        socket.emit('error', { message: 'Room already exists' });
        return;
      }
      
      // Create room
      const room = new Room({
        name: roomName,
        creator: username,
        isPrivate: isPrivate || false,
        users: [username]
      });
      
      // Save room
      await room.save();
      
      // Add room to user's accessible rooms
      await User.findOneAndUpdate(
        { username },
        { $addToSet: { accessibleRooms: roomName } }
      );
      
      // Emit room created event
      socket.emit('roomCreated', { roomName });
      
      // Broadcast to all users that a new room is available (if public)
      if (!isPrivate) {
        socket.broadcast.emit('roomCreated', { roomName });
      }
      
      console.log(`Room created: ${roomName} by ${username}, isPrivate: ${isPrivate}`);
    } catch (error) {
      console.error('Error creating room:', error);
      socket.emit('error', { message: 'Error creating room: ' + error.message });
    }
  });
  
  // Get available rooms
  socket.on('getAvailableRooms', async ({ username }) => {
    try {
      // Get all public rooms
      const publicRooms = await Room.find({ isPrivate: false }).select('name');
      
      // Get user's accessible rooms
      const user = await User.findOne({ username });
      const accessibleRooms = user ? user.accessibleRooms : [];
      
      // Combine and deduplicate
      const allRooms = [...new Set([
        ...publicRooms.map(room => room.name),
        ...accessibleRooms
      ])];
      
      // Emit available rooms
      socket.emit('availableRooms', { rooms: allRooms });
    } catch (error) {
      console.error('Error getting available rooms:', error);
      socket.emit('error', { message: 'Error getting available rooms' });
    }
  });
  
  // Request room access
  socket.on('requestRoomAccess', async ({ username, roomName }) => {
    try {
      console.log(`Processing room access request: ${username} requesting access to ${roomName}`);
      
      // Find room
      const room = await Room.findOne({ name: roomName });
      
      if (!room) {
        console.error(`Room not found: ${roomName}`);
        socket.emit('error', { message: 'Room not found' });
        return;
      }
      
      // Check if room is private
      if (!room.isPrivate) {
        console.log(`Room ${roomName} is public, granting access automatically`);
        
        // Add room to user's accessible rooms
        await User.findOneAndUpdate(
          { username },
          { $addToSet: { accessibleRooms: roomName } }
        );
        
        // Add user to room
        if (!room.users.includes(username)) {
          room.users.push(username);
          await room.save();
        }
        
        // Emit room access response to requester
        socket.emit('roomAccessResponse', {
          requestId: uuidv4(),
          approved: true,
          roomName
        });
        
        return;
      }
      
      // Check if user already has access
      const user = await User.findOne({ username });
      if (user && user.accessibleRooms && user.accessibleRooms.includes(roomName)) {
        console.log(`User ${username} already has access to room ${roomName}`);
        socket.emit('error', { message: 'You already have access to this room' });
        return;
      }
      
      // Check if request already exists
      const existingRequest = await RoomRequest.findOne({
        username,
        roomName,
        status: 'pending'
      });
      
      if (existingRequest) {
        console.log(`Request already exists for ${username} to access ${roomName}`);
        socket.emit('error', { message: 'Request already sent' });
        return;
      }
      
      // Create request ID
      const requestId = uuidv4();
      
      // Create room request
      const roomRequest = new RoomRequest({
        id: requestId,
        username,
        roomName,
        status: 'pending'
      });
      
      // Save request
      await roomRequest.save();
      
      // Find room creator's socket
      const creatorSocket = findSocketByUsername(room.creator);
      
      if (creatorSocket) {
        // Emit room access request to creator
        io.to(creatorSocket.id).emit('roomAccessRequest', {
          requestId,
          requester: username,
          roomName
        });
        console.log(`Sent roomAccessRequest to creator ${room.creator}`);
      } else {
        console.log(`Room creator ${room.creator} is not online, request saved to database`);
      }
      
      console.log(`Room access request processed: ${username} requested access to ${roomName}`);
    } catch (error) {
      console.error('Error requesting room access:', error);
      socket.emit('error', { message: 'Error requesting room access: ' + error.message });
    }
  });
  
  // Respond to room access request
  socket.on('respondToRoomAccess', async ({ requestId, approved }) => {
    try {
      console.log(`Processing room access response: ${requestId}, approved: ${approved}`);
      
      // Find request
      const request = await RoomRequest.findOne({ id: requestId });
      
      if (!request) {
        console.error(`Request not found: ${requestId}`);
        socket.emit('error', { message: 'Request not found' });
        return;
      }
      
      console.log(`Found request:`, request);
      
      // Update request status
      request.status = approved ? 'approved' : 'rejected';
      await request.save();
      
      if (approved) {
        // Find room
        const room = await Room.findOne({ name: request.roomName });
        
        if (!room) {
          console.error(`Room not found: ${request.roomName}`);
          socket.emit('error', { message: 'Room not found' });
          return;
        }
        
        // Add user to room
        if (!room.users.includes(request.username)) {
          room.users.push(request.username);
          await room.save();
        }
        
        // Add room to user's accessible rooms
        const updatedUser = await User.findOneAndUpdate(
          { username: request.username },
          { $addToSet: { accessibleRooms: request.roomName } },
          { new: true }
        );
        
        console.log(`Updated accessible rooms for ${request.username}:`, updatedUser.accessibleRooms);
      }
      
      // Find requester's socket
      const requesterSocket = findSocketByUsername(request.username);
      
      if (requesterSocket) {
        // Emit room access response to requester
        io.to(requesterSocket.id).emit('roomAccessResponse', {
          requestId,
          approved,
          roomName: request.roomName
        });
        console.log(`Sent roomAccessResponse to requester ${request.username}`);
      }
      
      console.log(`Room access response processed: ${request.username}'s request for ${request.roomName} was ${approved ? 'approved' : 'rejected'}`);
    } catch (error) {
      console.error('Error responding to room access:', error);
      socket.emit('error', { message: 'Error responding to room access' });
    }
  });
  
  // Invite user to room
  socket.on('inviteUserToRoom', async ({ inviter, invitee, roomName }) => {
    try {
      console.log(`Processing invitation: ${inviter} inviting ${invitee} to ${roomName}`);
      
      // Find room
      const room = await Room.findOne({ name: roomName });
      
      if (!room) {
        console.error(`Room not found: ${roomName}`);
        socket.emit('error', { message: 'Room not found' });
        return;
      }
      
      // Check if inviter has access to room (either as creator or in users array)
      if (room.creator !== inviter && !room.users.includes(inviter)) {
        console.error(`Inviter ${inviter} does not have access to room ${roomName}`);
        socket.emit('error', { message: 'You do not have access to this room' });
        return;
      }
      
      // Check if invitee already has access
      if (room.users.includes(invitee)) {
        console.log(`Invitee ${invitee} already has access to room ${roomName}`);
        socket.emit('error', { message: `${invitee} already has access to this room` });
        return;
      }
      
      // Check if invitation already exists
      const existingInvitation = await RoomInvitation.findOne({
        inviter,
        invitee,
        roomName,
        status: 'pending'
      });
      
      if (existingInvitation) {
        console.log(`Invitation already exists for ${invitee} to room ${roomName}`);
        socket.emit('error', { message: `Invitation already sent to ${invitee}` });
        return;
      }
      
      // Create invitation ID
      const invitationId = uuidv4();
      
      // Create room invitation
      const roomInvitation = new RoomInvitation({
        id: invitationId,
        inviter,
        invitee,
        roomName,
        status: 'pending'
      });
      
      // Save invitation
      await roomInvitation.save();
      
      // Find invitee's socket
      const inviteeSocket = findSocketByUsername(invitee);
      
      if (inviteeSocket) {
        // Emit room invitation to invitee
        io.to(inviteeSocket.id).emit('roomInvitation', {
          invitationId,
          roomName,
          inviter
        });
        
        console.log(`Sent roomInvitation to invitee ${invitee}`);
      } else {
        console.log(`Invitee ${invitee} is not online, invitation saved to database`);
      }
      
      // Confirm to inviter
      socket.emit('invitationSent', {
        invitationId,
        invitee,
        roomName
      });
      
      console.log(`Room invitation processed: ${inviter} invited ${invitee} to ${roomName}`);
    } catch (error) {
      console.error('Error inviting user to room:', error);
      socket.emit('error', { message: 'Error inviting user to room: ' + error.message });
    }
  });
  
  // Respond to room invitation
  socket.on('respondToRoomInvitation', async ({ invitationId, accepted, username }) => {
    try {
      console.log(`Processing invitation response: ${invitationId}, accepted: ${accepted}, username: ${username}`);
      
      // Find invitation
      const invitation = await RoomInvitation.findOne({ id: invitationId });
      
      if (!invitation) {
        console.error(`Invitation not found: ${invitationId}`);
        socket.emit('error', { message: 'Invitation not found' });
        return;
      }
      
      // Verify the user is the invitee
      if (invitation.invitee !== username) {
        console.error(`User ${username} is not the invitee for invitation ${invitationId}`);
        socket.emit('error', { message: 'You are not the invitee for this invitation' });
        return;
      }
      
      console.log(`Found invitation:`, invitation);
      
      // Update invitation status
      invitation.status = accepted ? 'accepted' : 'declined';
      await invitation.save();
      
      if (accepted) {
        // Find room
        const room = await Room.findOne({ name: invitation.roomName });
        
        if (!room) {
          console.error(`Room not found: ${invitation.roomName}`);
          socket.emit('error', { message: 'Room not found' });
          return;
        }
        
        console.log(`Adding ${username} to room ${room.name} (private: ${room.isPrivate})`);
        
        // Add user to room's users array
        if (!room.users.includes(invitation.invitee)) {
          room.users.push(invitation.invitee);
          await room.save();
          console.log(`Added ${invitation.invitee} to room.users:`, room.users);
        }
        
        // Add room to user's accessible rooms
        const updatedUser = await User.findOneAndUpdate(
          { username: invitation.invitee },
          { $addToSet: { accessibleRooms: invitation.roomName } },
          { new: true }
        );
        
        console.log(`Updated accessible rooms for ${invitation.invitee}:`, updatedUser.accessibleRooms);
      }
      
      // Find inviter's socket
      const inviterSocket = findSocketByUsername(invitation.inviter);
      
      if (inviterSocket) {
        // Emit room invitation response to inviter
        io.to(inviterSocket.id).emit('roomInvitationResponse', {
          invitationId,
          accepted,
          roomName: invitation.roomName,
          invitee: invitation.invitee
        });
        console.log(`Sent roomInvitationResponse to inviter ${invitation.inviter}`);
      }
      
      // Emit room invitation response to invitee (the current user)
      socket.emit('roomInvitationResponse', {
        invitationId,
        accepted,
        roomName: invitation.roomName
      });
      console.log(`Sent roomInvitationResponse to invitee ${invitation.invitee}`);
      
      // If accepted, also emit availableRooms update to the invitee
      if (accepted) {
        try {
          // Get all public rooms
          const publicRooms = await Room.find({ isPrivate: false }).select('name');
          
          // Get user's accessible rooms
          const user = await User.findOne({ username: invitation.invitee });
          const accessibleRooms = user ? user.accessibleRooms : [];
          
          // Combine and deduplicate
          const allRooms = [...new Set([
            ...publicRooms.map(room => room.name),
            ...accessibleRooms
          ])];
          
          // Emit available rooms
          socket.emit('availableRooms', { rooms: allRooms });
          console.log(`Sent updated availableRooms to ${invitation.invitee}:`, allRooms);
        } catch (error) {
          console.error('Error getting available rooms:', error);
        }
      }
      
      console.log(`Room invitation response processed: ${invitation.invitee} ${accepted ? 'accepted' : 'declined'} invitation to ${invitation.roomName}`);
    } catch (error) {
      console.error('Error responding to room invitation:', error);
      socket.emit('error', { message: 'Error responding to room invitation: ' + error.message });
    }
  });
  
  // Get all users for invitations
  socket.on('getAllUsers', async () => {
    try {
      console.log('Fetching all users for invitations');
      
      // Get all users
      const users = await User.find().select('username');
      
      // Extract usernames
      const usernames = users.map(user => user.username);
      
      console.log(`Found ${usernames.length} users`);
      
      // Emit all users
      socket.emit('allUsers', {
        users: usernames
      });
    } catch (error) {
      console.error('Error getting all users:', error);
      socket.emit('error', { message: 'Error getting all users' });
    }
  });
  
  // Delete room
  socket.on('deleteRoom', async ({ username, roomName }) => {
    try {
      console.log(`Request to delete room ${roomName} by ${username}`);
      
      // Don't allow deletion of default rooms
      if (roomName === 'general' || roomName === 'tech' || roomName === 'random') {
        console.error(`Cannot delete default room: ${roomName}`);
        socket.emit('error', { message: 'Cannot delete default rooms' });
        return;
      }
      
      // Find the room
      const room = await Room.findOne({ name: roomName });
      
      if (!room) {
        socket.emit('error', { message: 'Room not found' });
        return;
      }
      
      // Check if user is the creator
      if (room.creator !== username) {
        socket.emit('error', { message: 'Only the room creator can delete this room' });
        return;
      }
      
      // Delete all messages in the room
      await Message.deleteMany({ room: roomName });
      
      // Delete all invitations for this room
      await RoomInvitation.deleteMany({ roomName });
      
      // Delete all access requests for this room
      await RoomRequest.deleteMany({ roomName });
      
      // Remove room from users' accessible rooms
      await User.updateMany(
        { accessibleRooms: roomName },
        { $pull: { accessibleRooms: roomName } }
      );
      
      // Delete the room
      await Room.deleteOne({ name: roomName });
      
      console.log(`Room ${roomName} deleted by ${username}`);
      
      // Notify all users that the room was deleted
      io.emit('roomDeleted', { roomName });
      
      // Confirm to the user who deleted the room
      socket.emit('roomDeleteSuccess', { roomName });
    } catch (error) {
      console.error('Error deleting room:', error);
      socket.emit('error', { message: 'Error deleting room: ' + error.message });
    }
  });
  
  // Disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected');
    
    // Find username for this socket
    let disconnectedUser = null;
    for (const [username, socketId] of userSocketMap.entries()) {
      if (socketId === socket.id) {
        disconnectedUser = username;
        break;
      }
    }
    
    if (disconnectedUser) {
      console.log(`User ${disconnectedUser} disconnected`);
      userSocketMap.delete(disconnectedUser);
    }
    
    // Remove user from all rooms
    for (const room in onlineUsers) {
      if (disconnectedUser) {
        onlineUsers[room] = onlineUsers[room].filter(user => user !== disconnectedUser);
      } else {
        onlineUsers[room] = onlineUsers[room].filter(user => {
          const userSocket = findSocketByUsername(user);
          return userSocket && userSocket.id !== socket.id;
        });
      }
      
      // Send room data
      io.to(room).emit('roomData', {
        room,
        users: onlineUsers[room]
      });
    }
  });
});

const PORT = process.env.PORT || 5001;

// Connect to MongoDB
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    
    // Ensure default room exists
    ensureDefaultRoomExists();
    
    // Start server
    server.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Error connecting to MongoDB:', err);
  });