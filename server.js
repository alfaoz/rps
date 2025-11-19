const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const readline = require('readline');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static(__dirname));

const rooms = {};
const playerPings = {};

function generateRoomId() {
  const chars = 'ABCDEFGHJKLMNOPQRSTUVWXYZ0123456789'; // Excludes I to avoid confusion
  let result = '';
  for (let i = 0; i < 5; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Auto-ping all connected players every 2 seconds
  const pingTracker = setInterval(() => {
    const timestamp = Date.now();
    socket.emit('server_ping', { timestamp });
  }, 2000);

  socket.on('create_room', () => {
    const roomId = generateRoomId();
    rooms[roomId] = {
      players: [socket.id],
      choices: {},
      ready: {},
      resetRequests: {},
      scores: {}
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

    // Initialize scores for both players
    if (room.players.length === 2) {
      room.scores[room.players[0]] = 0;
      room.scores[room.players[1]] = 0;
    }

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

      // Update scores
      if (result === 'player1') {
        room.scores[p1]++;
      } else if (result === 'player2') {
        room.scores[p2]++;
      }

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
      // Reset server-side scores
      room.players.forEach(playerId => {
        room.scores[playerId] = 0;
      });
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

  socket.on('server_pong', ({ timestamp }) => {
    // Calculate latency and store it
    const latency = Date.now() - timestamp;
    playerPings[socket.id] = latency;

    // Broadcast this player's ping to others in their room (for debug mode)
    for (const roomId in rooms) {
      const room = rooms[roomId];
      if (room.players.includes(socket.id)) {
        // Send opponent's ping to this player
        room.players.forEach(playerId => {
          if (playerId !== socket.id && playerPings[playerId]) {
            socket.emit('opponent_ping', { ping: playerPings[playerId] });
          }
        });

        // Send this player's ping to opponents
        socket.to(roomId).emit('opponent_ping', { ping: latency });
        break;
      }
    }
  });

  socket.on('ping_request', ({ timestamp }) => {
    // Respond with the timestamp for latency calculation (for debug mode)
    socket.emit('ping_response', { timestamp });
  });

  socket.on('send_reaction', ({ roomId, emoji }) => {
    // Broadcast the reaction to the other player in the room
    socket.to(roomId).emit('receive_reaction', { emoji });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    clearInterval(pingTracker);
    delete playerPings[socket.id];

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
  console.log('type /help for server commands');
});

// Server console commands
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: ''
});

rl.on('line', (input) => {
  const cmd = input.trim();

  if (cmd === '/help') {
    console.log('\nserver commands:');
    console.log('  /games  - list all active games');
    console.log('  /ping   - show ping for all players');
    console.log('  /scores - show scores for all games');
    console.log('  /help   - show this help message\n');
  }

  else if (cmd === '/games') {
    const gameCount = Object.keys(rooms).length;
    console.log(`\nactive games: ${gameCount}`);
    for (const roomId in rooms) {
      const room = rooms[roomId];
      console.log(`  room ${roomId}: ${room.players.length} player(s)`);
    }
    console.log('');
  }

  else if (cmd === '/ping') {
    console.log('\nplayer pings:');
    let hasPings = false;
    for (const playerId in playerPings) {
      console.log(`  ${playerId.substring(0, 8)}...: ${playerPings[playerId]}ms`);
      hasPings = true;
    }
    if (!hasPings) {
      console.log('  no ping data available');
    }
    console.log('');
  }

  else if (cmd === '/scores') {
    console.log('\ngame scores:');
    let hasGames = false;
    for (const roomId in rooms) {
      const room = rooms[roomId];
      if (room.players.length === 2) {
        const p1 = room.players[0];
        const p2 = room.players[1];
        const score1 = room.scores[p1] || 0;
        const score2 = room.scores[p2] || 0;
        console.log(`  room ${roomId}:`);
        console.log(`    player 1 (${p1.substring(0, 8)}...): ${score1}`);
        console.log(`    player 2 (${p2.substring(0, 8)}...): ${score2}`);
        hasGames = true;
      }
    }
    if (!hasGames) {
      console.log('  no active games with 2 players');
    }
    console.log('');
  }
});
