import React, { useState } from 'react';
import "./Style/chat.css";

function ChatModals({ 
  showInviteUsers,
  setShowInviteUsers,
  inviteUsersList,
  userStatuses,
  room,
  newRoomName,
  handleInviteUsers,
  connectionStatus
}) {
  const [selectedUsersToInvite, setSelectedUsersToInvite] = useState([]);
  
  const toggleUserSelection = (user) => {
    if (selectedUsersToInvite.includes(user)) {
      setSelectedUsersToInvite(prev => prev.filter(u => u !== user));
    } else {
      setSelectedUsersToInvite(prev => [...prev, user]);
    }
  };
  
  const handleInviteSubmit = () => {
    handleInviteUsers(selectedUsersToInvite);
    setSelectedUsersToInvite([]);
  };

  return (
    <>
      {/* Invite Users Modal */}
      {showInviteUsers && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>Invite Users to {newRoomName || room}</h3>
              <button 
                className="close-modal"
                onClick={() => {
                  setShowInviteUsers(false);
                  setSelectedUsersToInvite([]);
                }}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="users-list">
                {inviteUsersList.length > 0 ? (
                  inviteUsersList.map((user) => (
                    <div 
                      key={user} 
                      className={`user-item ${selectedUsersToInvite.includes(user) ? 'selected' : ''}`}
                      onClick={() => toggleUserSelection(user)}
                    >
                      <span className={`status-indicator ${userStatuses[user] || 'offline'}`}></span>
                      <span className="user-name">{user}</span>
                      {selectedUsersToInvite.includes(user) && (
                        <span className="selected-indicator">✓</span>
                      )}
                    </div>
                  ))
                ) : (
                  <p className="no-users">No users available to invite</p>
                )}
              </div>
            </div>
            <div className="modal-footer">
              <button 
                className="cancel-btn"
                onClick={() => {
                  setShowInviteUsers(false);
                  setSelectedUsersToInvite([]);
                }}
              >
                Cancel
              </button>
              <button 
                className="invite-users-btn"
                onClick={handleInviteSubmit}
                disabled={selectedUsersToInvite.length === 0}
              >
                Invite Selected Users
              </button>
            </div>
          </div>
        </div>
      )}
      
      {connectionStatus !== 'connected' && (
        <div className={`connection-status ${connectionStatus}`}>
          {connectionStatus === 'connecting' && 'Connecting to server...'}
          {connectionStatus === 'error' && 'Error connecting to server. Please refresh the page.'}
          {connectionStatus === 'disconnected' && 'Disconnected from server. Trying to reconnect...'}
        </div>
      )}
    </>
  );
}

export default ChatModals; 