import React from 'react';
import "./Style/chat.css";

function Sidebar({ 
  username, 
  room, 
  availableRooms, 
  onlineUsers, 
  userStatuses,
  selectedUser,
  pendingRoomRequests,
  roomInvitations,
  roomAccessRequests,
  handleRoomChange,
  createNewRoom,
  handleRoomAccessResponse,
  handleInvitationResponse,
  startDirectMessage,
  logOut
}) {
  const [showNewRoomInput, setShowNewRoomInput] = React.useState(false);
  const [newRoomName, setNewRoomName] = React.useState('');
  const [isPrivateRoom, setIsPrivateRoom] = React.useState(false);
  const [showRoomRequests, setShowRoomRequests] = React.useState(false);
  const [showRoomInvitations, setShowRoomInvitations] = React.useState(false);
  
  // Count pending invitations
  const pendingInvitationsCount = roomInvitations.filter(inv => inv.status === 'pending').length;
  
  const handleCreateRoom = () => {
    if (newRoomName.trim()) {
      createNewRoom(newRoomName, isPrivateRoom);
      setShowNewRoomInput(false);
      setNewRoomName('');
      setIsPrivateRoom(false);
    }
  };

  return (
    <div className="chat-sidebar">
      <div className="logo">
        <h2>ChatApp</h2>
      </div>
      <div className="rooms">
        <div className="rooms-header">
          <h3>Rooms</h3>
          <div className="room-actions">
            <button 
              className="add-room-btn"
              onClick={() => setShowNewRoomInput(!showNewRoomInput)}
              title="Create new room"
            >
              +
            </button>
            <button 
              className={`requests-btn ${pendingRoomRequests.length > 0 ? 'has-requests' : ''}`}
              onClick={() => {
                setShowRoomRequests(!showRoomRequests);
                setShowRoomInvitations(false);
              }}
              title="Room access requests"
            >
              <span className="request-icon">🔔</span>
              {pendingRoomRequests.length > 0 && (
                <span className="request-badge">{pendingRoomRequests.length}</span>
              )}
            </button>
            <button 
              className={`invitations-btn ${pendingInvitationsCount > 0 ? 'has-invitations' : ''}`}
              onClick={() => {
                setShowRoomInvitations(!showRoomInvitations);
                setShowRoomRequests(false);
              }}
              title="Room invitations"
            >
              <span className="invitation-icon">✉️</span>
              {pendingInvitationsCount > 0 && (
                <span className="invitation-badge">{pendingInvitationsCount}</span>
              )}
            </button>
          </div>
        </div>
        
        {showNewRoomInput && (
          <div className="new-room-container">
            <div className="new-room-input">
              <input
                type="text"
                value={newRoomName}
                onChange={(e) => setNewRoomName(e.target.value)}
                placeholder="Room name..."
              />
              <button onClick={handleCreateRoom}>Create</button>
            </div>
            <div className="room-privacy-toggle">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={isPrivateRoom}
                  onChange={() => setIsPrivateRoom(!isPrivateRoom)}
                />
                <span className="toggle-text">Private Room</span>
              </label>
            </div>
          </div>
        )}
        
        {showRoomRequests && pendingRoomRequests.length > 0 && (
          <div className="room-requests">
            <h4>Access Requests</h4>
            <ul>
              {pendingRoomRequests.map((request) => (
                <li key={request.id} className="request-item">
                  <span>{request.username} wants to join #{request.room}</span>
                  <div className="request-actions">
                    <button 
                      className="approve-btn"
                      onClick={() => handleRoomAccessResponse(request.id, true)}
                    >
                      ✓
                    </button>
                    <button 
                      className="deny-btn"
                      onClick={() => handleRoomAccessResponse(request.id, false)}
                    >
                      ✕
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
        
        {showRoomInvitations && roomInvitations.length > 0 && (
          <div className="room-invitations">
            <h4>Room Invitations</h4>
            <ul>
              {roomInvitations.map((invitation) => (
                <li key={invitation.id} className="invitation-item">
                  <div className="invitation-info">
                    <span>{invitation.from} invited you to #{invitation.room}</span>
                    <span className={`invitation-status ${invitation.status}`}>
                      {invitation.status}
                    </span>
                  </div>
                  {invitation.status === 'pending' && (
                    <div className="invitation-actions">
                      <button 
                        className="accept-btn"
                        onClick={() => handleInvitationResponse(invitation.id, true)}
                      >
                        Accept
                      </button>
                      <button 
                        className="decline-btn"
                        onClick={() => handleInvitationResponse(invitation.id, false)}
                      >
                        Decline
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        
        {roomAccessRequests.length > 0 && (
          <div className="my-room-requests">
            <h4>My Pending Requests</h4>
            <ul>
              {roomAccessRequests.map((request, index) => (
                <li key={index} className="my-request-item">
                  <span>#{request.room}</span>
                  <span className={`request-status ${request.status}`}>
                    {request.status}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        
        <ul className="room-list">
          {availableRooms.map((roomName) => (
            <li
              key={roomName}
              className={room === roomName && !selectedUser ? 'active' : ''}
              onClick={() => handleRoomChange(roomName)}
            >
              <span className="room-icon">#</span> {roomName}
            </li>
          ))}
        </ul>
      </div>
      <div className="online-users">
        <h3>Users</h3>
        <ul>
          {onlineUsers.map((user) => (
            <li 
              key={user} 
              className={`${user === username ? 'current-user' : ''} ${selectedUser === user ? 'active' : ''}`}
              onClick={() => user !== username && startDirectMessage(user)}
            >
              <span className={`status-indicator ${userStatuses[user] || 'offline'}`}></span>
              {user} {user === username && '(you)'}
            </li>
          ))}
        </ul>
      </div>
      <button className="logout-btn" onClick={logOut}>
        Logout
      </button>
    </div>
  );
}

export default Sidebar; 