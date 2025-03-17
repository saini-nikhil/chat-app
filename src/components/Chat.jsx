import React, { useState, useEffect, useRef } from 'react';
import { v4 as uuidv4 } from 'uuid';
import Sidebar from './Sidebar';
import MessageArea from './MessageArea';
import ChatModals from './ChatModals';
import { 
  initializeSocket, 
  API_URL, 
  fetchMessages, 
  fetchAvailableRooms, 
  fetchRoomRequests, 
  fetchRoomInvitations,
  checkRoomCreator
} from '../utils/socketUtils';
import "./Style/chat.css";

function Chat({ logOut }) {
  // State variables
  const [messages, setMessages] = useState([]);
  const [room, setRoom] = useState('general');
  const [availableRooms, setAvailableRooms] = useState(['general', 'tech', 'random']);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [typingUsers, setTypingUsers] = useState([]);
  const [userStatuses, setUserStatuses] = useState({});
  const [newRoomName, setNewRoomName] = useState('');
  const [selectedUser, setSelectedUser] = useState(null);
  const [pendingRoomRequests, setPendingRoomRequests] = useState([]);
  const [roomAccessRequests, setRoomAccessRequests] = useState([]);
  const [requestingAccess, setRequestingAccess] = useState(false);
  const [showInviteUsers, setShowInviteUsers] = useState(false);
  const [inviteUsersList, setInviteUsersList] = useState([]);
  const [roomInvitations, setRoomInvitations] = useState([]);
  const [roomCreator, setRoomCreator] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  
  const socketRef = useRef();
  const prevRoom = useRef(null);
  
  const username = localStorage.getItem('username');

  // Initialize socket connection
  useEffect(() => {
    const socketCallbacks = {
      onConnect: () => {
        setConnectionStatus('connected');
        
        // Get existing messages
        loadMessages(room);
        
        // Get available rooms
        loadAvailableRooms();
        
        // Get pending room requests
        loadRoomRequests();
        
        // Get room invitations
        loadRoomInvitations();
        
        // Get all users for invitations
        fetchAllUsers();
      },
      onConnectError: (error) => {
        setConnectionStatus('error');
      },
      onDisconnect: () => {
        setConnectionStatus('disconnected');
      },
      onMessage: (message) => {
        setMessages(prevMessages => [...prevMessages, message]);
      },
      onMessageUpdated: ({ messageId, status, seenBy }) => {
        setMessages(prevMessages => 
          prevMessages.map(msg => 
            msg.id === messageId ? { ...msg, status, seenBy } : msg
          )
        );
      },
      onMessageStatusUpdate: ({ messageId, status }) => {
        setMessages(prevMessages => 
          prevMessages.map(msg => 
            msg.id === messageId ? { ...msg, status } : msg
          )
        );
      },
      onRoomData: (users) => {
        setOnlineUsers(users);
        
        // Update status for all users in the room
        const newStatuses = { ...userStatuses };
        users.forEach(user => {
          newStatuses[user] = 'online';
        });
        setUserStatuses(newStatuses);
      },
      onTyping: (users) => {
        setTypingUsers(users);
      },
      onRoomCreated: (roomName) => {
        // Add to available rooms if not already there
        setAvailableRooms(prevRooms => {
          if (!prevRooms.includes(roomName)) {
            return [...prevRooms, roomName];
          }
          return prevRooms;
        });
        
        // Switch to the newly created room
        setRoom(roomName);
        
        // Refresh available rooms to ensure everything is up to date
        setTimeout(() => {
          loadAvailableRooms();
        }, 500);
      },
      onAvailableRooms: (rooms) => {
        setAvailableRooms(rooms);
      },
      onRoomAccessRequest: ({ requestId, requester, roomName }) => {
        setPendingRoomRequests(prev => [...prev, { id: requestId, username: requester, room: roomName }]);
      },
      onRoomAccessResponse: ({ requestId, approved, roomName }) => {
        if (approved) {
          // Add room to available rooms if approved
          setAvailableRooms(prev => {
            if (!prev.includes(roomName)) {
              return [...prev, roomName];
            }
            return prev;
          });
          
          // Remove from pending requests
          setRoomAccessRequests(prev => prev.filter(req => req.room !== roomName));
          
          // Switch to the room if approved
          setRoom(roomName);
          
          // Refresh available rooms
          loadAvailableRooms();
        } else {
          // Update request status to rejected
          setRoomAccessRequests(prev => 
            prev.map(req => 
              req.room === roomName 
                ? { ...req, status: 'rejected' } 
                : req
            )
          );
        }
      },
      onRoomInvitation: ({ invitationId, roomName, inviter }) => {
        // Check if this invitation already exists
        setRoomInvitations(prev => {
          const exists = prev.some(inv => inv.id === invitationId);
          if (!exists) {
            return [...prev, { id: invitationId, room: roomName, from: inviter, status: 'pending' }];
          }
          return prev;
        });
        
        // Refresh invitations from server
        loadRoomInvitations();
      },
      onRoomInvitationResponse: ({ invitationId, accepted, roomName }) => {
        if (accepted) {
          // Add room to available rooms if accepted
          setAvailableRooms(prev => {
            if (!prev.includes(roomName)) {
              return [...prev, roomName];
            }
            return prev;
          });
          
          // Refresh available rooms
          loadAvailableRooms();
        }
        
        // Update invitation status
        setRoomInvitations(prev => 
          prev.map(inv => 
            inv.id === invitationId 
              ? { ...inv, status: accepted ? 'accepted' : 'declined' } 
              : inv
          )
        );
      },
      onAllUsers: (users) => {
        setInviteUsersList(users.filter(user => user !== username));
      },
      onError: (message) => {
        console.error('Socket error:', message);
      },
      onRoomDeleted: (roomName) => {
        // Remove room from available rooms
        setAvailableRooms(prev => prev.filter(r => r !== roomName));
        
        // If currently in the deleted room, switch to general
        if (room === roomName) {
          setRoom('general');
        }
      },
      onRoomDeleteSuccess: (roomName) => {
        console.log(`Successfully deleted room ${roomName}`);
      }
    };
    
    socketRef.current = initializeSocket(username, room, socketCallbacks);
    
    // Cleanup on component unmount
    return () => {
      console.log('Disconnecting socket');
      socketRef.current.disconnect();
    };
  }, []);
  
  // Effect for room changes
  useEffect(() => {
    if (!socketRef.current) return;
    
    console.log(`Room changed to ${room}`);
    
    // Leave previous room if any
    if (prevRoom.current) {
      console.log(`Leaving room ${prevRoom.current}`);
      socketRef.current.emit('leave', { username, room: prevRoom.current });
    }
    
    // Join new room
    socketRef.current.emit('join', { username, room });
    
    // Fetch existing messages
    loadMessages(room);
    
    // Reset typing users
    setTypingUsers([]);
    
    // Check if user is room creator
    if (!room.startsWith('dm_')) {
      loadRoomCreator(room);
    } else {
      setRoomCreator(null);
    }
    
    // Update previous room
    prevRoom.current = room;
  }, [room]);
  
  // Effect to refresh available rooms when invitations change
  useEffect(() => {
    if (roomInvitations.some(inv => inv.status === 'accepted')) {
      loadAvailableRooms();
    }
  }, [roomInvitations]);
  
  // Helper functions
  const loadMessages = async (roomName) => {
    const messagesData = await fetchMessages(roomName);
    setMessages(messagesData);
  };
  
  const loadAvailableRooms = async () => {
    const rooms = await fetchAvailableRooms(username);
    setAvailableRooms(rooms);
  };
  
  const loadRoomRequests = async () => {
    const requests = await fetchRoomRequests(username);
    setRoomAccessRequests(requests);
  };
  
  const loadRoomInvitations = async () => {
    const invitations = await fetchRoomInvitations(username, roomInvitations);
    setRoomInvitations(invitations);
  };
  
  const loadRoomCreator = async (roomName) => {
    const roomData = await checkRoomCreator(roomName);
    if (roomData) {
      setRoomCreator(roomData.creator);
    } else {
      setRoomCreator(null);
    }
  };
  
  const fetchAllUsers = () => {
    console.log('Fetching all users for invitations');
    socketRef.current.emit('getAllUsers');
  };
  
  const sendMessageToServer = (messageText) => {
    try {
      // Generate a unique ID for the message
      const messageId = uuidv4();
      const timestamp = new Date();
      
      // Create message object
      const messageObj = {
        id: messageId,
        sender: username,
        room,
        text: messageText.trim(),
        timestamp,
        status: 'sent',
        seenBy: []
      };
      
      // Add message to local state immediately for better UX
      setMessages(prevMessages => [...prevMessages, messageObj]);
      
      // Emit message to server
      socketRef.current.emit('sendMessage', messageObj);
    } catch (error) {
      console.error('Error sending message:', error);
    }
  };
  
  const handleRoomChange = (newRoom) => {
    // Check if user has access to this room
    if (!availableRooms.includes(newRoom) && !newRoom.startsWith('dm_')) {
      // Request access to the room
      requestRoomAccess(newRoom);
      return;
    }
    
    setRoom(newRoom);
    setSelectedUser(null);
  };
  
  const createNewRoom = (roomName, isPrivate) => {
    socketRef.current.emit('createRoom', { 
      username,
      roomName,
      isPrivate
    });
    
    // If private room, show invite users dialog
    if (isPrivate) {
      setTimeout(() => {
        setShowInviteUsers(true);
        setNewRoomName(roomName);
      }, 500);
    }
  };
  
  const requestRoomAccess = (roomName) => {
    console.log(`Requesting access to room ${roomName}`);
    
    // Show requesting access indicator
    setRequestingAccess(true);
    
    // Emit socket event to request access
    socketRef.current.emit('requestRoomAccess', { 
      username, 
      roomName 
    });
    
    // Add to pending requests locally
    setRoomAccessRequests(prev => {
      // Check if request already exists
      if (prev.some(req => req.room === roomName)) {
        return prev;
      }
      return [...prev, { room: roomName, status: 'pending' }];
    });
    
    // Hide requesting access indicator after 3 seconds
    setTimeout(() => {
      setRequestingAccess(false);
    }, 3000);
  };
  
  const handleRoomAccessResponse = (requestId, approved) => {
    console.log(`Responding to room access request ${requestId}, approved: ${approved}`);
    
    // Emit socket event to respond to request
    socketRef.current.emit('respondToRoomAccess', {
      requestId,
      approved
    });
    
    // Locally update the request status
    setPendingRoomRequests(prev => 
      prev.filter(req => req.id !== requestId)
    );
    
    // Refresh room requests after a short delay
    setTimeout(() => {
      loadRoomRequests();
    }, 500);
  };
  
  const handleInviteUsers = (selectedUsers) => {
    if (selectedUsers.length > 0) {
      // Store the current room name to ensure it's not lost during state updates
      const targetRoomName = newRoomName || room;
      console.log(`Inviting users to ${targetRoomName}:`, selectedUsers);
      
      // Invite each selected user
      selectedUsers.forEach(invitee => {
        socketRef.current.emit('inviteUserToRoom', { 
          inviter: username,
          invitee,
          roomName: targetRoomName
        });
      });
      
      // Close modal
      setShowInviteUsers(false);
      
      // If this was for a new room, clear the new room name
      if (newRoomName) {
        setNewRoomName('');
      }
    }
  };
  
  const handleInvitationResponse = (invitationId, accepted) => {
    console.log(`Responding to invitation ${invitationId}, accepted: ${accepted}`);
    
    // Emit socket event to respond to invitation
    socketRef.current.emit('respondToRoomInvitation', {
      invitationId,
      accepted,
      username
    });
    
    // Locally update the invitation status
    setRoomInvitations(prev => 
      prev.map(inv => 
        inv.id === invitationId 
          ? { ...inv, status: accepted ? 'accepted' : 'declined' } 
          : inv
      )
    );
    
    // If accepted, add the room to available rooms if not already there
    if (accepted) {
      const invitation = roomInvitations.find(inv => inv.id === invitationId);
      if (invitation) {
        setAvailableRooms(prev => {
          if (!prev.includes(invitation.room)) {
            return [...prev, invitation.room];
          }
          return prev;
        });
        
        // Switch to the new room
        setRoom(invitation.room);
      }
    }
    
    // Refresh available rooms after a short delay
    setTimeout(() => {
      loadAvailableRooms();
      loadRoomInvitations();
    }, 500);
  };
  
  const startDirectMessage = (recipient) => {
    // Create a DM room name that's consistent regardless of who initiates
    const users = [username, recipient].sort();
    const dmRoom = `dm_${users[0]}_${users[1]}`;
    
    setRoom(dmRoom);
    setSelectedUser(recipient);
  };
  
  const handleTyping = (isTyping) => {
    // Emit typing event
    socketRef.current.emit('typing', {
      username,
      room,
      isTyping
    });
  };
  
  const deleteRoom = () => {
    if (window.confirm(`Are you sure you want to delete the room "${room}"? This action cannot be undone.`)) {
      console.log(`Deleting room ${room}`);
      socketRef.current.emit('deleteRoom', { username, roomName: room });
    }
  };

  return (
    <div className="chat-container">
      <Sidebar 
        username={username}
        room={room}
        availableRooms={availableRooms}
        onlineUsers={onlineUsers}
        userStatuses={userStatuses}
        selectedUser={selectedUser}
        pendingRoomRequests={pendingRoomRequests}
        roomInvitations={roomInvitations}
        roomAccessRequests={roomAccessRequests}
        handleRoomChange={handleRoomChange}
        createNewRoom={createNewRoom}
        handleRoomAccessResponse={handleRoomAccessResponse}
        handleInvitationResponse={handleInvitationResponse}
        startDirectMessage={startDirectMessage}
        logOut={logOut}
      />
      
      <MessageArea 
        username={username}
        room={room}
        messages={messages}
        typingUsers={typingUsers}
        selectedUser={selectedUser}
        roomCreator={roomCreator}
        requestingAccess={requestingAccess}
        sendMessageToServer={sendMessageToServer}
        handleTyping={handleTyping}
        setShowInviteUsers={setShowInviteUsers}
        deleteRoom={deleteRoom}
      />
      
      <ChatModals 
        showInviteUsers={showInviteUsers}
        setShowInviteUsers={setShowInviteUsers}
        inviteUsersList={inviteUsersList}
        userStatuses={userStatuses}
        room={room}
        newRoomName={newRoomName}
        handleInviteUsers={handleInviteUsers}
        connectionStatus={connectionStatus}
      />
    </div>
  );
}

export default Chat; 