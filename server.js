const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static(__dirname));

const rooms = {};

function generateRoomId() {
  return Math.random().toString(36).substring(2, 7).toUpperCase();
}

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('create_room', () => {
    const roomId = generateRoomId();
    rooms[roomId] = {
      players: [socket.id],
      choices: {},
      ready: {},
      resetRequests: {}
    };
    socket.join(roomId);
    socket.emit('room_created', roomId);
    console.log('Room created:', roomId);
  });

  socket.on('join_room', (roomId) => {
    const room = rooms[roomId];
    if (!room) {
      socket.emit('error', 'Room not found');
      return;
    }
    if (room.players.length >= 2) {
      socket.emit('error', 'Room is full');
      return;
    }
    room.players.push(socket.id);
    socket.join(roomId);
    socket.emit('room_joined', roomId);
    io.to(roomId).emit('player_joined', { playerCount: room.players.length });
    console.log('Player joined room:', roomId);
  });

  socket.on('make_choice', ({ roomId, choice }) => {
    const room = rooms[roomId];
    if (!room) return;

    room.choices[socket.id] = choice;

    const playerIndex = room.players.indexOf(socket.id);
    io.to(roomId).emit('player_ready', { player: playerIndex + 1 });

    if (Object.keys(room.choices).length === 2) {
      const [p1, p2] = room.players;
      const choice1 = room.choices[p1];
      const choice2 = room.choices[p2];

      const result = determineWinner(choice1, choice2);

      io.to(roomId).emit('game_result', {
        player1: choice1,
        player2: choice2,
        result: result
      });

      room.choices = {};
    }
  });

  socket.on('ready_for_next', ({ roomId }) => {
    const room = rooms[roomId];
    if (!room) return;

    room.ready[socket.id] = true;

    // Notify the other player that this player is ready
    socket.to(roomId).emit('opponent_ready');

    if (Object.keys(room.ready).length === 2) {
      room.ready = {};
      io.to(roomId).emit('start_round');
    }
  });

  socket.on('request_reset', ({ roomId }) => {
    const room = rooms[roomId];
    if (!room) return;

    room.resetRequests[socket.id] = true;

    // Notify the other player
    socket.to(roomId).emit('reset_requested');

    // If both players want to reset
    if (Object.keys(room.resetRequests).length === 2) {
      room.resetRequests = {};
      io.to(roomId).emit('score_reset');
    }
  });

  socket.on('cancel_reset', ({ roomId }) => {
    const room = rooms[roomId];
    if (!room) return;

    delete room.resetRequests[socket.id];

    // Notify the other player
    socket.to(roomId).emit('reset_cancelled');
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    for (const roomId in rooms) {
      const room = rooms[roomId];
      const index = room.players.indexOf(socket.id);
      if (index !== -1) {
        room.players.splice(index, 1);
        io.to(roomId).emit('player_left');
        if (room.players.length === 0) {
          delete rooms[roomId];
          console.log('Room deleted:', roomId);
        }
      }
    }
  });
});

function determineWinner(choice1, choice2) {
  if (choice1 === choice2) return 'tie';
  if (
    (choice1 === 'rock' && choice2 === 'scissors') ||
    (choice1 === 'paper' && choice2 === 'rock') ||
    (choice1 === 'scissors' && choice2 === 'paper')
  ) {
    return 'player1';
  }
  return 'player2';
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`rock paper scissors server running on http://localhost:${PORT} :3`);
});
