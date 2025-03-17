import io from 'socket.io-client';
import { v4 as uuidv4 } from 'uuid';

const ENDPOINT = 'http://localhost:5001';
export const API_URL = ENDPOINT;

// Initialize socket connection
export const initializeSocket = (username, room, callbacks) => {
  console.log('Connecting to socket server at', ENDPOINT);
  
  const socket = io(ENDPOINT, {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionAttempts: 5,
    reconnectionDelay: 1000
  });
  
  // Setup connection event handlers
  socket.on('connect', () => {
    console.log('Connected to socket server with ID:', socket.id);
    callbacks.onConnect();
    
    // Join default room
    socket.emit('join', { username, room });
  });
  
  socket.on('connect_error', (error) => {
    console.error('Socket connection error:', error);
    callbacks.onConnectError(error);
  });
  
  socket.on('disconnect', () => {
    console.log('Disconnected from socket server');
    callbacks.onDisconnect();
  });
  
  // Message events
  socket.on('message', (message) => {
    console.log('Received message:', message);
    callbacks.onMessage(message);
    
    // Mark message as seen if we're not the sender
    if (message.sender !== username) {
      socket.emit('messageSeen', { messageId: message.id, room });
    }
  });
  
  socket.on('messageUpdated', ({ messageId, status, seenBy }) => {
    callbacks.onMessageUpdated({ messageId, status, seenBy });
  });
  
  socket.on('messageStatusUpdate', ({ messageId, status }) => {
    callbacks.onMessageStatusUpdate({ messageId, status });
  });
  
  // Room events
  socket.on('roomData', ({ users }) => {
    callbacks.onRoomData(users);
  });
  
  socket.on('typing', ({ users }) => {
    callbacks.onTyping(users);
  });
  
  socket.on('roomCreated', ({ roomName }) => {
    console.log(`Room created: ${roomName}`);
    callbacks.onRoomCreated(roomName);
  });
  
  socket.on('availableRooms', ({ rooms }) => {
    callbacks.onAvailableRooms(rooms);
  });
  
  socket.on('roomAccessRequest', ({ requestId, requester, roomName }) => {
    callbacks.onRoomAccessRequest({ requestId, requester, roomName });
  });
  
  socket.on('roomAccessResponse', ({ requestId, approved, roomName }) => {
    console.log(`Received room access response: ${requestId}, approved: ${approved}, room: ${roomName}`);
    callbacks.onRoomAccessResponse({ requestId, approved, roomName });
  });
  
  socket.on('roomInvitation', ({ invitationId, roomName, inviter }) => {
    console.log('Received room invitation:', { invitationId, roomName, inviter });
    callbacks.onRoomInvitation({ invitationId, roomName, inviter });
  });
  
  socket.on('roomInvitationResponse', ({ invitationId, accepted, roomName }) => {
    console.log('Room invitation response:', { invitationId, accepted, roomName });
    callbacks.onRoomInvitationResponse({ invitationId, accepted, roomName });
  });
  
  socket.on('allUsers', ({ users }) => {
    callbacks.onAllUsers(users);
  });
  
  socket.on('error', ({ message }) => {
    console.error('Socket error:', message);
    callbacks.onError(message);
  });
  
  socket.on('roomDeleted', ({ roomName }) => {
    console.log(`Room ${roomName} was deleted`);
    callbacks.onRoomDeleted(roomName);
  });
  
  socket.on('roomDeleteSuccess', ({ roomName }) => {
    console.log(`Successfully deleted room ${roomName}`);
    callbacks.onRoomDeleteSuccess(roomName);
  });
  
  return socket;
};

// API functions
export const fetchMessages = async (roomName) => {
  try {
    console.log(`Fetching messages for room ${roomName}`);
    const response = await fetch(`${API_URL}/api/messages/${roomName}`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`Received ${data.length} messages for room ${roomName}`);
    
    // Normalize message format to handle both old and new formats
    return data.map(msg => ({
      id: msg.id || uuidv4(), // Generate ID if not present
      sender: msg.sender,
      text: msg.text || msg.content || '',
      timestamp: msg.timestamp || msg.createdAt || new Date(),
      status: msg.status || 'delivered',
      seenBy: msg.seenBy || []
    }));
  } catch (error) {
    console.error('Error fetching messages:', error);
    return []; // Return empty array on error
  }
};

export const fetchAvailableRooms = async (username) => {
  try {
    console.log('Fetching available rooms for', username);
    
    // Get user-specific rooms
    const userRoomsResponse = await fetch(`${ENDPOINT}/api/user-rooms/${username}`);
    if (!userRoomsResponse.ok) {
      throw new Error(`HTTP error! status: ${userRoomsResponse.status}`);
    }
    const userRooms = await userRoomsResponse.json();
    console.log('User-specific rooms:', userRooms);
    
    // Get public rooms
    const publicRoomsResponse = await fetch(`${ENDPOINT}/api/rooms`);
    if (!publicRoomsResponse.ok) {
      throw new Error(`HTTP error! status: ${publicRoomsResponse.status}`);
    }
    const publicRooms = await publicRoomsResponse.json();
    console.log('Public rooms:', publicRooms);
    
    // Get rooms where user is explicitly added (for private rooms)
    const userInRoomsResponse = await fetch(`${ENDPOINT}/api/rooms-with-user/${username}`);
    let roomsWithUser = [];
    if (userInRoomsResponse.ok) {
      roomsWithUser = await userInRoomsResponse.json();
      console.log('Rooms with user as member:', roomsWithUser);
    }
    
    // Combine and deduplicate rooms
    const allRooms = [...new Set([...userRooms, ...publicRooms, ...roomsWithUser])];
    console.log('All available rooms:', allRooms);
    
    return allRooms;
  } catch (error) {
    console.error('Error fetching available rooms:', error);
    return [];
  }
};

export const fetchRoomRequests = async (username) => {
  try {
    console.log('Fetching room access requests for', username);
    const response = await fetch(`${API_URL}/api/room-requests/${username}`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('Received room access requests:', data);
    
    return data;
  } catch (error) {
    console.error('Error fetching room access requests:', error);
    return [];
  }
};

export const fetchRoomInvitations = async (username, currentInvitations = []) => {
  try {
    console.log('Fetching room invitations for', username);
    const response = await fetch(`${ENDPOINT}/api/room-invitations/${username}`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('Received room invitations:', data);
    
    // Filter out non-pending invitations if we already have them in state
    const currentPendingIds = currentInvitations
      .filter(inv => inv.status === 'pending')
      .map(inv => inv.id);
    
    // Keep existing non-pending invitations and add new pending ones
    return [
      ...currentInvitations.filter(inv => inv.status !== 'pending'),
      ...data.filter(inv => inv.status === 'pending' || !currentPendingIds.includes(inv.id))
    ];
  } catch (error) {
    console.error('Error fetching room invitations:', error);
    return currentInvitations;
  }
};

export const checkRoomCreator = async (roomName) => {
  try {
    console.log(`Checking room details for ${roomName}`);
    const response = await fetch(`${API_URL}/api/rooms/${roomName}`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const roomData = await response.json();
    console.log('Room data:', roomData);
    
    return roomData;
  } catch (error) {
    console.error('Error checking room details:', error);
    return null;
  }
}; 