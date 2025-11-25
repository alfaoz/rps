const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const readline = require('readline');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const geoip = require('geoip-lite');

const app = express();
const server = http.createServer(app);

// ===================
// ENVIRONMENT CONFIG
// ===================
const BASE_PATH = process.env.BASE_PATH || '';
const io = socketIo(server, {
  path: `${BASE_PATH}/socket.io`
});

app.use(express.json());
app.use(cookieParser());

// Serve config to frontend
app.get(`${BASE_PATH}/config.js`, (req, res) => {
  res.type('application/javascript');
  res.send(`window.RPS_CONFIG = { basePath: "${BASE_PATH}" };`);
});

// ===================
// ADMIN CONFIGURATION
// ===================
let adminCredentials = {
  user: process.env.ADMIN_USER || 'admin',
  pass: process.env.ADMIN_PASS || 'rps2024'
};

// Session timeout (5 minutes of no ping = disconnect)
const SESSION_TIMEOUT = 5 * 60 * 1000;

// Basic auth middleware for admin routes
function adminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Authentication required');
  }

  const credentials = Buffer.from(auth.slice(6), 'base64').toString();
  const [user, pass] = credentials.split(':');

  if (user === adminCredentials.user && pass === adminCredentials.pass) {
    next();
  } else {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Invalid credentials');
  }
}

// ===================
// DATA STRUCTURES
// ===================
const rooms = {};
const sessionToRoom = {};
const sessionToSocket = {};
const socketToSession = {};
const disconnectTimers = {};

// Admin tracking data
const sessionData = {};      // sessionId -> { ip, lastPing, lastActivity, connectedAt, userAgent }
const roomLogs = {};         // roomId -> [{ time, event, data }]
const serverStats = {
  totalGamesPlayed: 0,
  totalConnections: 0,
  startTime: Date.now()
};

// AI tracking data
const aiPlayers = {};        // sessionId -> { roomId, slot, difficulty, state }
const AI_SESSION_PREFIX = 'ai_';

// AI state structure for each AI player
function createAIState(difficulty) {
  return {
    difficulty: difficulty || 'hard',
    opponentHistory: [],
    aiHistory: [],
    resultHistory: [],
    overallFrequency: { rock: 0, paper: 0, scissors: 0 },
    recentFrequency: { rock: 0, paper: 0, scissors: 0 },
    afterWin: { rock: 0, paper: 0, scissors: 0 },
    afterLoss: { rock: 0, paper: 0, scissors: 0 },
    afterTie: { rock: 0, paper: 0, scissors: 0 },
    transitionMatrix: {
      'rock->rock': 0, 'rock->paper': 0, 'rock->scissors': 0,
      'paper->rock': 0, 'paper->paper': 0, 'paper->scissors': 0,
      'scissors->rock': 0, 'scissors->paper': 0, 'scissors->scissors': 0
    },
    currentStreak: { choice: null, count: 0 },
    longestStreak: { choice: null, count: 0 }
  };
}

// ===================
// SESSION CLEANUP
// ===================
function cleanupInactiveSessions() {
  const now = Date.now();
  let cleaned = 0;

  for (const sessionId in sessionToSocket) {
    const data = sessionData[sessionId];
    if (!data || !data.lastActivity) continue;

    const inactive = now - data.lastActivity;
    if (inactive > SESSION_TIMEOUT) {
      const socketId = sessionToSocket[sessionId];
      const socket = io.sockets.sockets.get(socketId);

      if (socket) {
        serverLog(`Session ${sessionId.slice(0, 8)}... timed out (${Math.floor(inactive / 1000)}s inactive)`);
        socket.disconnect(true);
      }

      // Clean up mappings
      const roomId = sessionToRoom[sessionId];
      if (roomId && rooms[roomId]) {
        removePlayerFromRoom(sessionId, roomId);
      }

      delete sessionToSocket[sessionId];
      delete sessionData[sessionId];
      cleaned++;
    }
  }

  return cleaned;
}

// Run cleanup every minute
setInterval(cleanupInactiveSessions, 60000);

// ===================
// LOGGING SYSTEM
// ===================
function logToRoom(roomId, event, data = {}) {
  if (!roomLogs[roomId]) {
    roomLogs[roomId] = [];
  }
  const entry = {
    time: Date.now(),
    event,
    data
  };
  roomLogs[roomId].push(entry);

  // Keep only last 100 entries per room
  if (roomLogs[roomId].length > 100) {
    roomLogs[roomId].shift();
  }
}

function serverLog(message) {
  // Minimal server logging - only critical stuff
  const time = new Date().toLocaleTimeString();
  console.log(`[${time}] ${message}`);
}

// ===================
// STATIC FILES
// ===================
// Serve admin page before static middleware
app.get(`${BASE_PATH}/admin`, adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Serve static files but exclude admin.html from direct access
app.use(BASE_PATH || '/', (req, res, next) => {
  if (req.path === '/admin.html') {
    return res.status(404).send('Not found');
  }
  next();
});
app.use(BASE_PATH || '/', express.static(__dirname));

// ===================
// ADMIN API ENDPOINTS
// ===================
app.get(`${BASE_PATH}/api/admin/stats`, adminAuth, (req, res) => {
  const uptime = Date.now() - serverStats.startTime;
  res.json({
    uptime,
    totalGamesPlayed: serverStats.totalGamesPlayed,
    totalConnections: serverStats.totalConnections,
    activeRooms: Object.keys(rooms).length,
    activeSessions: Object.keys(sessionToSocket).length
  });
});

app.get(`${BASE_PATH}/api/admin/rooms`, adminAuth, (req, res) => {
  const roomList = [];
  for (const roomId in rooms) {
    const room = rooms[roomId];
    const players = [];

    for (let i = 0; i < 2; i++) {
      const sessionId = room.sessions[i];
      if (sessionId) {
        const data = sessionData[sessionId] || {};
        const ip = data.ip || 'unknown';
        players.push({
          slot: i + 1,
          sessionId: sessionId.slice(0, 8) + '...',
          ip: ip,
          country: getCountryCode(ip),
          ping: data.lastPing || null,
          connected: !!sessionToSocket[sessionId]
        });
      }
    }

    roomList.push({
      roomId,
      status: room.status,
      scores: room.scores,
      players,
      createdAt: room.createdAt,
      roundsPlayed: room.roundsPlayed || 0
    });
  }
  res.json(roomList);
});

app.get(`${BASE_PATH}/api/admin/room/:roomId/logs`, adminAuth, (req, res) => {
  const logs = roomLogs[req.params.roomId] || [];
  res.json(logs);
});

app.get(`${BASE_PATH}/api/admin/sessions`, adminAuth, (req, res) => {
  const sessions = [];
  const now = Date.now();
  for (const sessionId in sessionToSocket) {
    const data = sessionData[sessionId] || {};
    const roomId = sessionToRoom[sessionId];
    const ip = data.ip || 'unknown';
    sessions.push({
      sessionId: sessionId.slice(0, 8) + '...',
      fullSessionId: sessionId,
      ip: ip,
      country: getCountryCode(ip),
      ping: data.lastPing || null,
      roomId: roomId || null,
      connectedAt: data.connectedAt,
      lastActivity: data.lastActivity,
      inactiveSeconds: data.lastActivity ? Math.floor((now - data.lastActivity) / 1000) : null,
      userAgent: data.userAgent
    });
  }
  res.json(sessions);
});

app.post(`${BASE_PATH}/api/admin/kick/:sessionId`, adminAuth, (req, res) => {
  const { sessionId } = req.params;

  // Find full session ID from partial
  let fullSessionId = null;
  for (const sid in sessionToSocket) {
    if (sid.startsWith(sessionId.replace('...', ''))) {
      fullSessionId = sid;
      break;
    }
  }

  if (!fullSessionId) {
    return res.status(404).json({ error: 'Session not found' });
  }

  const socketId = sessionToSocket[fullSessionId];
  const socket = io.sockets.sockets.get(socketId);

  if (socket) {
    socket.disconnect(true);
  }

  // Clean up
  const roomId = sessionToRoom[fullSessionId];
  if (roomId && rooms[roomId]) {
    removePlayerFromRoom(fullSessionId, roomId);
  }

  delete sessionToSocket[fullSessionId];
  delete sessionData[fullSessionId];

  serverLog(`Admin kicked session ${fullSessionId.slice(0, 8)}...`);
  res.json({ success: true });
});

app.post(`${BASE_PATH}/api/admin/cleanup`, adminAuth, (req, res) => {
  const cleaned = cleanupInactiveSessions();
  res.json({ cleaned });
});

app.post(`${BASE_PATH}/api/admin/room/:roomId/delete`, adminAuth, (req, res) => {
  const { roomId } = req.params;

  const room = rooms[roomId];
  if (!room) {
    return res.status(404).json({ error: 'Room not found' });
  }

  // Notify all players in the room that it's being closed by admin
  emitToRoom(roomId, 'room_closed_by_admin');

  // Collect session IDs before removal (since removePlayerFromRoom modifies the array)
  const sessionIds = room.sessions.filter(sid => sid !== null);

  // Remove all players from the room (like being kicked)
  for (const sessionId of sessionIds) {
    if (sessionId) {
      removePlayerFromRoom(sessionId, roomId);
    }
  }

  // Log the admin deletion
  logToRoom(roomId, 'room_deleted_by_admin', { totalRounds: room.roundsPlayed || 0 });

  // Force delete the room if it still exists (removePlayerFromRoom auto-deletes when empty)
  if (rooms[roomId]) {
    delete rooms[roomId];
    // Schedule log cleanup (after 1 hour)
    setTimeout(() => {
      delete roomLogs[roomId];
    }, 3600000);
  }

  serverLog(`Admin deleted room ${roomId}`);
  res.json({ success: true, roomId });
});

// ===================
// GAME API
// ===================
app.get(`${BASE_PATH}/api/session`, (req, res) => {
  let sessionId = req.cookies.sessionId;

  if (!sessionId) {
    sessionId = uuidv4();
    res.cookie('sessionId', sessionId, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true
    });
  }

  res.json({ sessionId });
});

// ===================
// HELPER FUNCTIONS
// ===================
function generateRoomId() {
  const chars = 'ABCDEFGHJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 5; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  // Ensure unique
  if (rooms[result]) return generateRoomId();
  return result;
}

function getPlayerSlot(roomId, sessionId) {
  const room = rooms[roomId];
  if (!room) return -1;
  return room.sessions.indexOf(sessionId);
}

function getSocketForSession(sessionId) {
  return sessionToSocket[sessionId];
}

function emitToPlayer(roomId, slot, event, data) {
  const room = rooms[roomId];
  if (!room || !room.sessions[slot]) return;
  const socketId = getSocketForSession(room.sessions[slot]);
  if (socketId) {
    io.to(socketId).emit(event, data);
  }
}

function emitToRoom(roomId, event, data) {
  emitToPlayer(roomId, 0, event, data);
  emitToPlayer(roomId, 1, event, data);
}

function getClientIp(socket) {
  return socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim()
    || socket.handshake.address;
}

function getCountryCode(ip) {
  // Skip localhost and private IPs
  if (!ip || ip === '::1' || ip === '127.0.0.1' || ip.startsWith('::ffff:127.') || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    return null;
  }

  // Remove ::ffff: prefix if present
  const cleanIp = ip.replace(/^::ffff:/, '');

  const geo = geoip.lookup(cleanIp);
  return geo ? geo.country : null;
}

// ===================
// AI SYSTEM
// ===================

// Helper: Returns what beats a choice
function beats(choice) {
  const counters = { rock: 'paper', paper: 'scissors', scissors: 'rock' };
  return counters[choice];
}

// Helper: Get most frequent choice from frequency object
function getMostFrequent(freq) {
  let max = -1;
  let mostFrequent = 'rock';
  for (const choice of ['rock', 'paper', 'scissors']) {
    if (freq[choice] > max) {
      max = freq[choice];
      mostFrequent = choice;
    }
  }
  return mostFrequent;
}

// Helper: Sum of frequency object values
function sumFreq(freq) {
  return freq.rock + freq.paper + freq.scissors;
}

// Helper: Weighted random choice
function weightedRandomChoice(weights) {
  const total = weights.rock + weights.paper + weights.scissors;
  if (total === 0) {
    const choices = ['rock', 'paper', 'scissors'];
    return choices[Math.floor(Math.random() * choices.length)];
  }

  let rand = Math.random() * total;
  for (const choice of ['rock', 'paper', 'scissors']) {
    rand -= weights[choice];
    if (rand <= 0) return choice;
  }
  return 'rock';
}

// Update AI state with latest game result
function updateAIState(aiState, opponentChoice, aiChoice, result) {
  // Add to histories
  aiState.opponentHistory.push(opponentChoice);
  aiState.aiHistory.push(aiChoice);
  aiState.resultHistory.push(result);

  // Update overall frequency
  aiState.overallFrequency[opponentChoice]++;

  // Update recent frequency (last 10)
  const recentMoves = aiState.opponentHistory.slice(-10);
  aiState.recentFrequency = { rock: 0, paper: 0, scissors: 0 };
  for (const move of recentMoves) {
    aiState.recentFrequency[move]++;
  }

  // Update psychological patterns (what they play AFTER win/loss/tie)
  if (aiState.resultHistory.length >= 2) {
    const prevResult = aiState.resultHistory[aiState.resultHistory.length - 2];
    if (prevResult === 'win') {
      aiState.afterWin[opponentChoice]++;
    } else if (prevResult === 'loss') {
      aiState.afterLoss[opponentChoice]++;
    } else {
      aiState.afterTie[opponentChoice]++;
    }
  }

  // Update transition matrix
  if (aiState.opponentHistory.length >= 2) {
    const from = aiState.opponentHistory[aiState.opponentHistory.length - 2];
    const to = opponentChoice;
    aiState.transitionMatrix[`${from}->${to}`]++;
  }

  // Update streak
  if (aiState.opponentHistory.length >= 2) {
    const last = aiState.opponentHistory[aiState.opponentHistory.length - 1];
    const secondLast = aiState.opponentHistory[aiState.opponentHistory.length - 2];

    if (last === secondLast) {
      if (aiState.currentStreak.choice === last) {
        aiState.currentStreak.count++;
      } else {
        aiState.currentStreak = { choice: last, count: 2 };
      }

      if (aiState.currentStreak.count > aiState.longestStreak.count) {
        aiState.longestStreak = { ...aiState.currentStreak };
      }
    } else {
      aiState.currentStreak = { choice: null, count: 0 };
    }
  }
}

// Easy difficulty: 70% random, 30% basic counter
function easyStrategy(aiState) {
  if (Math.random() < 0.7 || aiState.opponentHistory.length < 5) {
    const choices = ['rock', 'paper', 'scissors'];
    return choices[Math.floor(Math.random() * choices.length)];
  }

  const mostPlayed = getMostFrequent(aiState.overallFrequency);
  return beats(mostPlayed);
}

// Medium difficulty: Frequency + anti-repetition + loss-switching
function mediumStrategy(aiState) {
  if (aiState.opponentHistory.length < 3) {
    const choices = ['rock', 'paper', 'scissors'];
    return choices[Math.floor(Math.random() * choices.length)];
  }

  const weights = { rock: 33, paper: 33, scissors: 33 };

  // Factor 1: Recent frequency
  if (aiState.opponentHistory.length >= 5) {
    const recent = aiState.opponentHistory.slice(-10);
    for (const choice of recent) {
      weights[beats(choice)] += 4;
    }
  }

  // Factor 2: Anti-repetition
  if (aiState.opponentHistory.length >= 2) {
    const last = aiState.opponentHistory[aiState.opponentHistory.length - 1];
    const secondLast = aiState.opponentHistory[aiState.opponentHistory.length - 2];
    if (last === secondLast) {
      for (const choice of ['rock', 'paper', 'scissors']) {
        if (choice !== last) {
          weights[beats(choice)] += 3;
        }
      }
    }
  }

  // Factor 3: Post-loss switching
  if (aiState.resultHistory.length >= 1) {
    const lastResult = aiState.resultHistory[aiState.resultHistory.length - 1];
    if (lastResult === 'win') {
      const lastTheyPlayed = aiState.opponentHistory[aiState.opponentHistory.length - 1];
      for (const choice of ['rock', 'paper', 'scissors']) {
        if (choice !== lastTheyPlayed) {
          weights[beats(choice)] += 3;
        }
      }
    }
  }

  return weightedRandomChoice(weights);
}

// Hard difficulty: Multi-layer analysis
function hardStrategy(aiState) {
  if (aiState.opponentHistory.length < 3) {
    return 'rock'; // Statistically most common opener
  }

  const weights = { rock: 20, paper: 20, scissors: 20 };

  // LAYER 1: Frequency Analysis
  const recentMoves = aiState.opponentHistory.slice(-10);
  for (const choice of recentMoves) {
    weights[beats(choice)] += 2;
  }

  // LAYER 2: Psychological Patterns
  if (aiState.resultHistory.length >= 1) {
    const lastResult = aiState.resultHistory[aiState.resultHistory.length - 1];

    if (lastResult === 'win') {
      for (const choice of ['rock', 'paper', 'scissors']) {
        if (aiState.afterLoss[choice] > 0) {
          weights[beats(choice)] += aiState.afterLoss[choice] * 0.3;
        }
      }
    } else if (lastResult === 'loss') {
      const lastChoice = aiState.opponentHistory[aiState.opponentHistory.length - 1];
      weights[beats(lastChoice)] += 6;
      for (const choice of ['rock', 'paper', 'scissors']) {
        if (choice !== lastChoice) {
          weights[beats(choice)] += 4;
        }
      }
    } else {
      for (const choice of ['rock', 'paper', 'scissors']) {
        if (aiState.afterTie[choice] > 0) {
          weights[beats(choice)] += aiState.afterTie[choice] * 0.3;
        }
      }
    }
  }

  // LAYER 3: Streak Detection
  if (aiState.currentStreak.count >= 2) {
    const streakChoice = aiState.currentStreak.choice;
    const boost = aiState.currentStreak.count === 2 ? 5 : 10;

    for (const choice of ['rock', 'paper', 'scissors']) {
      if (choice !== streakChoice) {
        weights[beats(choice)] += boost;
      }
    }
  }

  // LAYER 4: Transition Patterns
  if (aiState.opponentHistory.length >= 2) {
    const lastChoice = aiState.opponentHistory[aiState.opponentHistory.length - 1];
    for (const nextChoice of ['rock', 'paper', 'scissors']) {
      const transitionKey = `${lastChoice}->${nextChoice}`;
      const count = aiState.transitionMatrix[transitionKey];
      if (count > 0) {
        weights[beats(nextChoice)] += count * 2.5;
      }
    }
  }

  return weightedRandomChoice(weights);
}

// Expert difficulty: All layers + meta-detection
function expertStrategy(aiState) {
  if (aiState.opponentHistory.length < 5) {
    return hardStrategy(aiState);
  }

  const weights = { rock: 10, paper: 10, scissors: 10 };

  // LAYER 1: Deep Frequency Analysis
  const overallMostPlayed = getMostFrequent(aiState.overallFrequency);
  const recentMostPlayed = getMostFrequent(aiState.recentFrequency);

  if (recentMostPlayed !== overallMostPlayed) {
    weights[beats(recentMostPlayed)] += 8;
  } else {
    weights[beats(overallMostPlayed)] += 5;
  }

  // LAYER 2: Multi-depth Psychological Model
  if (aiState.resultHistory.length >= 1) {
    const lastResult = aiState.resultHistory[aiState.resultHistory.length - 1];

    if (lastResult === 'win') {
      const lossPattern = getMostFrequent(aiState.afterLoss);
      const totalLosses = sumFreq(aiState.afterLoss);
      if (totalLosses > 0) {
        const lossPatternStrength = aiState.afterLoss[lossPattern] / totalLosses;
        if (lossPatternStrength > 0.6) {
          weights[beats(lossPattern)] += 15;
        } else {
          const lastPlayed = aiState.opponentHistory[aiState.opponentHistory.length - 1];
          for (const choice of ['rock', 'paper', 'scissors']) {
            if (choice !== lastPlayed) {
              weights[beats(choice)] += 8;
            }
          }
        }
      }
    } else if (lastResult === 'loss') {
      const winPattern = getMostFrequent(aiState.afterWin);
      const totalWins = sumFreq(aiState.afterWin);
      if (totalWins > 0) {
        const winPatternStrength = aiState.afterWin[winPattern] / totalWins;
        if (winPatternStrength > 0.6) {
          weights[beats(winPattern)] += 15;
        } else {
          const lastPlayed = aiState.opponentHistory[aiState.opponentHistory.length - 1];
          weights[beats(lastPlayed)] += 10;
          for (const choice of ['rock', 'paper', 'scissors']) {
            if (choice !== lastPlayed) {
              weights[beats(choice)] += 5;
            }
          }
        }
      }
    }
  }

  // LAYER 3: Advanced Streak & Anti-Pattern
  if (aiState.currentStreak.count >= 2) {
    const streakChoice = aiState.currentStreak.choice;
    const boredomFactor = Math.min(aiState.currentStreak.count * 0.3, 0.95);

    for (const choice of ['rock', 'paper', 'scissors']) {
      if (choice !== streakChoice) {
        weights[beats(choice)] += boredomFactor * 20;
      }
    }
  }

  // LAYER 4: Meta-Game Detection (detect if they're countering us)
  if (aiState.opponentHistory.length >= 10 && aiState.aiHistory.length >= 10) {
    let counteringCount = 0;
    for (let i = Math.max(0, aiState.aiHistory.length - 10); i < aiState.aiHistory.length - 1; i++) {
      const ourChoice = aiState.aiHistory[i];
      const theirNextChoice = aiState.opponentHistory[i + 1];
      if (theirNextChoice === beats(ourChoice)) {
        counteringCount++;
      }
    }

    if (counteringCount >= 6) {
      // They're countering us! Add randomness
      for (const choice of ['rock', 'paper', 'scissors']) {
        weights[choice] += 30;
      }
    } else {
      // Exploit harder
      for (const choice of ['rock', 'paper', 'scissors']) {
        weights[choice] *= 1.5;
      }
    }
  }

  return weightedRandomChoice(weights);
}

/**
 * Main AI Decision Function
 */
function makeAIDecision(aiSessionId, opponentLastChoice) {
  const aiPlayer = aiPlayers[aiSessionId];
  if (!aiPlayer || !aiPlayer.state) {
    const choices = ['rock', 'paper', 'scissors'];
    return choices[Math.floor(Math.random() * choices.length)];
  }

  const aiState = aiPlayer.state;

  let choice;
  switch (aiState.difficulty) {
    case 'easy':
      choice = easyStrategy(aiState);
      break;
    case 'medium':
      choice = mediumStrategy(aiState);
      break;
    case 'hard':
      choice = hardStrategy(aiState);
      break;
    case 'expert':
      choice = expertStrategy(aiState);
      break;
    default:
      choice = hardStrategy(aiState);
  }

  return choice;
}

function createAIPlayer(roomId, slot, difficulty = 'hard') {
  const aiSessionId = AI_SESSION_PREFIX + uuidv4();

  aiPlayers[aiSessionId] = {
    roomId,
    slot,
    difficulty,
    state: createAIState(difficulty)
  };

  // Track AI session data
  sessionData[aiSessionId] = {
    ip: 'AI',
    lastPing: 0,
    lastActivity: Date.now(),
    connectedAt: Date.now(),
    userAgent: `AI Bot (${difficulty})`
  };

  return aiSessionId;
}

function isAIPlayer(sessionId) {
  return sessionId && sessionId.startsWith(AI_SESSION_PREFIX);
}

function handleAITurn(roomId) {
  const room = rooms[roomId];
  if (!room || room.status !== 'playing') return;

  // Check if there's an AI player in this room
  for (let slot = 0; slot < 2; slot++) {
    const sessionId = room.sessions[slot];
    if (isAIPlayer(sessionId) && !room.choices[slot]) {
      // Get opponent's last choice (if any)
      const opponentSlot = slot === 0 ? 1 : 0;
      let opponentLastChoice = null;
      if (room.lastGameResult && room.lastGameResult.choices) {
        opponentLastChoice = room.lastGameResult.choices[opponentSlot];
      }

      const choice = makeAIDecision(sessionId, opponentLastChoice);

      // Delay AI choice slightly to feel more natural (500-1500ms)
      const delay = 500 + Math.random() * 1000;

      setTimeout(() => {
        // Double-check room still exists and AI hasn't chosen
        if (rooms[roomId] && !rooms[roomId].choices[slot]) {
          rooms[roomId].choices[slot] = choice;
          logToRoom(roomId, 'choice', { player: slot + 1, choice, ai: true });

          emitToRoom(roomId, 'player_ready', { player: slot + 1 });

          // Check if both players have chosen
          if (rooms[roomId].choices[0] && rooms[roomId].choices[1]) {
            resolveGame(roomId);
          }
        }
      }, delay);
    }
  }
}

// Update AI state after each round
function updateAIAfterRound(roomId, choices, result) {
  const room = rooms[roomId];
  if (!room || !room.hasAI) return;

  for (let slot = 0; slot < 2; slot++) {
    const sessionId = room.sessions[slot];
    if (isAIPlayer(sessionId)) {
      const aiPlayer = aiPlayers[sessionId];
      if (aiPlayer && aiPlayer.state) {
        const opponentSlot = slot === 0 ? 1 : 0;
        const opponentChoice = choices[opponentSlot];
        const aiChoice = choices[slot];

        // Determine result from AI's perspective
        let aiResult;
        if (result === 'tie') {
          aiResult = 'tie';
        } else if ((result === 'player1' && slot === 0) || (result === 'player2' && slot === 1)) {
          aiResult = 'win';
        } else {
          aiResult = 'loss';
        }

        updateAIState(aiPlayer.state, opponentChoice, aiChoice, aiResult);
      }
    }
  }
}

// ===================
// DISCONNECT HANDLING
// ===================
function startDisconnectGracePeriod(sessionId, roomId) {
  if (disconnectTimers[sessionId]) {
    clearTimeout(disconnectTimers[sessionId]);
  }

  const room = rooms[roomId];
  if (!room) return;

  const slot = getPlayerSlot(roomId, sessionId);
  if (slot === -1) return;

  logToRoom(roomId, 'player_disconnect', { player: slot + 1, sessionId: sessionId.slice(0, 8) });

  const otherSlot = slot === 0 ? 1 : 0;
  emitToPlayer(roomId, otherSlot, 'opponent_disconnected');

  disconnectTimers[sessionId] = setTimeout(() => {
    logToRoom(roomId, 'grace_period_expired', { player: slot + 1 });
    removePlayerFromRoom(sessionId, roomId);
  }, 10000);
}

function cancelDisconnectGracePeriod(sessionId) {
  if (disconnectTimers[sessionId]) {
    clearTimeout(disconnectTimers[sessionId]);
    delete disconnectTimers[sessionId];
  }
}

function removePlayerFromRoom(sessionId, roomId) {
  const room = rooms[roomId];
  if (!room) return;

  const slot = getPlayerSlot(roomId, sessionId);
  if (slot === -1) return;

  logToRoom(roomId, 'player_removed', { player: slot + 1 });

  room.sessions[slot] = null;
  room.scores[slot] = 0;
  room.choices[slot] = null;
  room.ready[slot] = false;
  room.resetRequests[slot] = false;

  delete sessionToRoom[sessionId];
  delete disconnectTimers[sessionId];
  // NOTE: Don't delete sessionToSocket here - socket is still connected
  // and player should be able to create/join new rooms

  const otherSlot = slot === 0 ? 1 : 0;
  if (room.sessions[otherSlot]) {
    emitToPlayer(roomId, otherSlot, 'player_left');
  }

  const hasPlayers = room.sessions[0] || room.sessions[1];
  if (!hasPlayers) {
    logToRoom(roomId, 'room_closed', { totalRounds: room.roundsPlayed || 0 });
    delete rooms[roomId];
    // Keep logs for a while, clean up after 1 hour
    setTimeout(() => {
      delete roomLogs[roomId];
    }, 3600000);
  }
}

function getGameStateForPlayer(roomId, slot) {
  const room = rooms[roomId];
  if (!room) return null;

  const otherSlot = slot === 0 ? 1 : 0;
  const playerCount = (room.sessions[0] ? 1 : 0) + (room.sessions[1] ? 1 : 0);

  return {
    roomId,
    playerIndex: slot + 1,
    myScore: room.scores[slot],
    theirScore: room.scores[otherSlot],
    status: room.status,
    myChoice: room.choices[slot],
    theirChose: !!room.choices[otherSlot],
    myReady: room.ready[slot],
    theirReady: room.ready[otherSlot],
    playerCount,
    roundStartTime: room.roundStartTime,
    timerDuration: room.timerDuration,
    lastGameResult: room.lastGameResult
  };
}

// ===================
// HELPER: Update session activity
// ===================
function updateActivity(sessionId) {
  if (sessionId && sessionData[sessionId]) {
    sessionData[sessionId].lastActivity = Date.now();
  }
}

// ===================
// SOCKET HANDLING
// ===================
io.on('connection', (socket) => {
  serverStats.totalConnections++;
  const clientIp = getClientIp(socket);

  socket.on('register_session', (sessionId) => {
    if (!sessionId) return;

    const oldSocketId = sessionToSocket[sessionId];
    sessionToSocket[sessionId] = socket.id;
    socketToSession[socket.id] = sessionId;

    // Track session data
    sessionData[sessionId] = {
      ...sessionData[sessionId],
      ip: clientIp,
      connectedAt: Date.now(),
      lastActivity: Date.now(),
      userAgent: socket.handshake.headers['user-agent']
    };

    const roomId = sessionToRoom[sessionId];

    if (roomId && rooms[roomId]) {
      const room = rooms[roomId];
      const slot = getPlayerSlot(roomId, sessionId);

      if (slot !== -1) {
        logToRoom(roomId, 'player_reconnect', { player: slot + 1, ip: clientIp });
        cancelDisconnectGracePeriod(sessionId);
        socket.join(roomId);

        const state = getGameStateForPlayer(roomId, slot);
        socket.emit('reconnected', state);

        const otherSlot = slot === 0 ? 1 : 0;
        if (room.sessions[otherSlot]) {
          emitToPlayer(roomId, otherSlot, 'player_reconnected');
        }

        if (room.status === 'playing') {
          socket.emit('start_round', {
            duration: room.timerDuration,
            serverTime: room.roundStartTime
          });
        }

        return;
      } else {
        delete sessionToRoom[sessionId];
      }
    }

    if (roomId && !rooms[roomId]) {
      delete sessionToRoom[sessionId];
    }

    socket.emit('session_registered');
  });

  socket.on('create_room', () => {
    const sessionId = socketToSession[socket.id];
    if (!sessionId) {
      socket.emit('error', 'No session');
      return;
    }

    const roomId = generateRoomId();
    rooms[roomId] = {
      sessions: [sessionId, null],
      scores: [0, 0],
      choices: [null, null],
      ready: [false, false],
      resetRequests: [false, false],
      status: 'waiting',
      timerDuration: 3,
      roundStartTime: 0,
      lastGameResult: null,
      createdAt: Date.now(),
      roundsPlayed: 0
    };

    sessionToRoom[sessionId] = roomId;
    socket.join(roomId);
    socket.emit('room_created', roomId);

    logToRoom(roomId, 'room_created', { creator: sessionId.slice(0, 8), ip: clientIp });
    serverLog(`Room ${roomId} created`);
  });

  socket.on('create_ai_room', () => {
    const sessionId = socketToSession[socket.id];
    if (!sessionId) {
      socket.emit('error', 'No session');
      return;
    }

    const roomId = generateRoomId();

    // Create AI player
    const aiSessionId = createAIPlayer(roomId, 1);

    rooms[roomId] = {
      sessions: [sessionId, aiSessionId],
      scores: [0, 0],
      choices: [null, null],
      ready: [false, false],
      resetRequests: [false, false],
      status: 'waiting',
      timerDuration: 3,
      roundStartTime: 0,
      lastGameResult: null,
      createdAt: Date.now(),
      roundsPlayed: 0,
      hasAI: true
    };

    sessionToRoom[sessionId] = roomId;
    sessionToRoom[aiSessionId] = roomId;
    socket.join(roomId);
    socket.emit('room_created', roomId);

    logToRoom(roomId, 'room_created', { creator: sessionId.slice(0, 8), ip: clientIp, ai: true });
    serverLog(`AI Room ${roomId} created`);

    // Start game after a short delay
    setTimeout(() => {
      if (rooms[roomId] && rooms[roomId].sessions[0] && rooms[roomId].sessions[1]) {
        startRound(roomId);
      }
    }, 1000);
  });

  socket.on('join_room', (roomId) => {
    const sessionId = socketToSession[socket.id];
    if (!sessionId) {
      socket.emit('error', 'No session');
      return;
    }

    const room = rooms[roomId];
    if (!room) {
      socket.emit('error', 'Room not found');
      return;
    }

    const existingSlot = getPlayerSlot(roomId, sessionId);
    if (existingSlot !== -1) {
      socket.join(roomId);
      socket.emit('room_joined', { roomId, playerIndex: existingSlot + 1 });
      return;
    }

    let slot = -1;
    if (!room.sessions[0]) slot = 0;
    else if (!room.sessions[1]) slot = 1;

    if (slot === -1) {
      socket.emit('error', 'Room is full');
      return;
    }

    room.sessions[slot] = sessionId;
    sessionToRoom[sessionId] = roomId;
    socket.join(roomId);

    logToRoom(roomId, 'player_joined', { player: slot + 1, ip: clientIp });

    socket.emit('room_joined', { roomId, playerIndex: slot + 1 });

    const otherSlot = slot === 0 ? 1 : 0;
    if (room.sessions[otherSlot]) {
      emitToPlayer(roomId, otherSlot, 'player_joined');
    }

    const playerCount = (room.sessions[0] ? 1 : 0) + (room.sessions[1] ? 1 : 0);
    if (playerCount === 2) {
      serverLog(`Game starting in room ${roomId}`);
      setTimeout(() => {
        if (rooms[roomId] && room.sessions[0] && room.sessions[1]) {
          startRound(roomId);
        }
      }, 1000);
    }
  });

  socket.on('make_choice', ({ roomId, choice }) => {
    const sessionId = socketToSession[socket.id];
    const room = rooms[roomId];
    if (!room || !sessionId) return;

    updateActivity(sessionId);

    const validChoices = ['rock', 'paper', 'scissors'];
    if (!validChoices.includes(choice)) return;

    const slot = getPlayerSlot(roomId, sessionId);
    if (slot === -1) return;

    // Prevent duplicate choices (idempotency)
    if (room.choices[slot]) return;

    // Validate game is in playing state
    if (room.status !== 'playing') return;

    room.choices[slot] = choice;
    logToRoom(roomId, 'choice', { player: slot + 1, choice });

    emitToRoom(roomId, 'player_ready', { player: slot + 1 });

    if (room.choices[0] && room.choices[1]) {
      resolveGame(roomId);
    }
  });

  socket.on('ready_for_next', ({ roomId }) => {
    const sessionId = socketToSession[socket.id];
    const room = rooms[roomId];
    if (!room || !sessionId) return;

    updateActivity(sessionId);

    const slot = getPlayerSlot(roomId, sessionId);
    if (slot === -1) return;

    // Prevent duplicate ready (idempotency)
    if (room.ready[slot]) return;

    room.ready[slot] = true;

    const otherSlot = slot === 0 ? 1 : 0;
    emitToPlayer(roomId, otherSlot, 'opponent_ready');

    // Auto-ready AI player if present
    if (room.hasAI && isAIPlayer(room.sessions[otherSlot]) && !room.ready[otherSlot]) {
      setTimeout(() => {
        if (rooms[roomId] && !rooms[roomId].ready[otherSlot]) {
          rooms[roomId].ready[otherSlot] = true;
          emitToPlayer(roomId, slot, 'opponent_ready');

          if (rooms[roomId].ready[0] && rooms[roomId].ready[1]) {
            rooms[roomId].ready = [false, false];
            startRound(roomId);
          }
        }
      }, 500);
    } else if (room.ready[0] && room.ready[1]) {
      room.ready = [false, false];
      startRound(roomId);
    }
  });

  socket.on('request_reset', ({ roomId }) => {
    const sessionId = socketToSession[socket.id];
    const room = rooms[roomId];
    if (!room || !sessionId) return;

    updateActivity(sessionId);

    const slot = getPlayerSlot(roomId, sessionId);
    if (slot === -1) return;

    room.resetRequests[slot] = true;

    const otherSlot = slot === 0 ? 1 : 0;
    emitToPlayer(roomId, otherSlot, 'reset_requested');

    if (room.resetRequests[0] && room.resetRequests[1]) {
      room.resetRequests = [false, false];
      room.scores = [0, 0];
      logToRoom(roomId, 'score_reset', {});
      emitToRoom(roomId, 'score_reset');
    }
  });

  socket.on('cancel_reset', ({ roomId }) => {
    const sessionId = socketToSession[socket.id];
    const room = rooms[roomId];
    if (!room || !sessionId) return;

    const slot = getPlayerSlot(roomId, sessionId);
    if (slot === -1) return;

    room.resetRequests[slot] = false;

    const otherSlot = slot === 0 ? 1 : 0;
    emitToPlayer(roomId, otherSlot, 'reset_cancelled');
  });

  socket.on('ping_request', ({ timestamp }) => {
    socket.emit('ping_response', { timestamp });

    // Track ping and activity for admin
    const sessionId = socketToSession[socket.id];
    if (sessionId && sessionData[sessionId]) {
      const ping = Date.now() - timestamp;
      sessionData[sessionId].lastPing = ping;
      sessionData[sessionId].lastActivity = Date.now();
    }
  });

  socket.on('send_reaction', ({ roomId, emoji }) => {
    const sessionId = socketToSession[socket.id];
    const room = rooms[roomId];
    if (!room || !sessionId) return;

    const slot = getPlayerSlot(roomId, sessionId);
    if (slot === -1) return;

    const otherSlot = slot === 0 ? 1 : 0;
    emitToPlayer(roomId, otherSlot, 'receive_reaction', { emoji });
  });

  socket.on('leave_game', () => {
    const sessionId = socketToSession[socket.id];
    if (!sessionId) return;

    // Cancel any pending grace period
    cancelDisconnectGracePeriod(sessionId);

    const roomId = sessionToRoom[sessionId];
    if (roomId && rooms[roomId]) {
      logToRoom(roomId, 'player_left_intentionally', { sessionId: sessionId.slice(0, 8) });
      removePlayerFromRoom(sessionId, roomId);
    }
    // NOTE: Don't delete socketToSession - session persists for new rooms
  });

  socket.on('disconnect', () => {
    const sessionId = socketToSession[socket.id];

    if (!sessionId) return;

    delete socketToSession[socket.id];

    const roomId = sessionToRoom[sessionId];
    if (roomId && rooms[roomId]) {
      startDisconnectGracePeriod(sessionId, roomId);
    }
  });
});

// ===================
// GAME LOGIC
// ===================
function startRound(roomId) {
  const room = rooms[roomId];
  if (!room) return;

  room.status = 'playing';
  room.roundStartTime = Date.now();
  room.choices = [null, null];
  room.roundsPlayed = (room.roundsPlayed || 0) + 1;

  logToRoom(roomId, 'round_start', { round: room.roundsPlayed });

  emitToRoom(roomId, 'start_round', {
    duration: room.timerDuration,
    serverTime: room.roundStartTime
  });

  // Trigger AI turn if there's an AI player
  if (room.hasAI) {
    handleAITurn(roomId);
  }
}

function resolveGame(roomId) {
  const room = rooms[roomId];
  if (!room) return;

  const choice1 = room.choices[0];
  const choice2 = room.choices[1];

  const result = determineWinner(choice1, choice2);

  if (result === 'player1') {
    room.scores[0]++;
  } else if (result === 'player2') {
    room.scores[1]++;
  }

  room.lastGameResult = {
    choices: [choice1, choice2],
    result: result,
    scores: [...room.scores]
  };

  logToRoom(roomId, 'round_result', {
    choices: [choice1, choice2],
    result,
    scores: [...room.scores]
  });

  serverStats.totalGamesPlayed++;

  emitToPlayer(roomId, 0, 'game_result', {
    myChoice: choice1,
    theirChoice: choice2,
    result: result === 'player1' ? 'win' : result === 'player2' ? 'lose' : 'tie',
    myScore: room.scores[0],
    theirScore: room.scores[1]
  });

  emitToPlayer(roomId, 1, 'game_result', {
    myChoice: choice2,
    theirChoice: choice1,
    result: result === 'player2' ? 'win' : result === 'player1' ? 'lose' : 'tie',
    myScore: room.scores[1],
    theirScore: room.scores[0]
  });

  // Update AI state with this round's result
  updateAIAfterRound(roomId, [choice1, choice2], result);

  room.choices = [null, null];
  room.status = 'waiting';
}

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

// ===================
// SERVER START
// ===================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  serverLog(`Server running on http://localhost:${PORT}${BASE_PATH}/`);
  serverLog(`Admin panel: http://localhost:${PORT}${BASE_PATH}/admin`);
  console.log('Type /help for server commands\n');
});

// ===================
// CONSOLE COMMANDS
// ===================
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: ''
});

rl.on('line', (input) => {
  const cmd = input.trim();

  if (cmd === '/help') {
    console.log('\nServer commands:');
    console.log('  /status              - server status');
    console.log('  /rooms               - list active rooms');
    console.log('  /sessions            - list connected sessions');
    console.log('  /cleanup             - force cleanup inactive sessions');
    console.log('  /adminset user,pass  - set admin credentials');
    console.log('  /help                - show this help\n');
  }

  else if (cmd === '/status') {
    const uptime = Math.floor((Date.now() - serverStats.startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const mins = Math.floor((uptime % 3600) / 60);
    console.log(`\nServer Status:`);
    console.log(`  Uptime: ${hours}h ${mins}m`);
    console.log(`  Active rooms: ${Object.keys(rooms).length}`);
    console.log(`  Connected sessions: ${Object.keys(sessionToSocket).length}`);
    console.log(`  Total games played: ${serverStats.totalGamesPlayed}`);
    console.log(`  Total connections: ${serverStats.totalConnections}\n`);
  }

  else if (cmd === '/rooms') {
    const roomCount = Object.keys(rooms).length;
    console.log(`\nActive rooms: ${roomCount}`);
    for (const roomId in rooms) {
      const room = rooms[roomId];
      const p1 = room.sessions[0] ? 'P1' : '--';
      const p2 = room.sessions[1] ? 'P2' : '--';
      console.log(`  ${roomId}: [${p1}] [${p2}] ${room.status} (${room.roundsPlayed || 0} rounds)`);
    }
    console.log('');
  }

  else if (cmd === '/sessions') {
    const count = Object.keys(sessionToSocket).length;
    console.log(`\nConnected sessions: ${count}`);
    for (const sessionId in sessionToSocket) {
      const data = sessionData[sessionId] || {};
      const roomId = sessionToRoom[sessionId] || '-';
      const inactive = data.lastActivity ? Math.floor((Date.now() - data.lastActivity) / 1000) : '?';
      console.log(`  ${sessionId.slice(0, 8)}... | ${data.ip || '?'} | room: ${roomId} | ping: ${data.lastPing || '?'}ms | inactive: ${inactive}s`);
    }
    console.log('');
  }

  else if (cmd === '/cleanup') {
    const cleaned = cleanupInactiveSessions();
    console.log(`\nCleaned up ${cleaned} inactive session(s)\n`);
  }

  else if (cmd.startsWith('/adminset ')) {
    const args = cmd.slice(10).trim();
    const [newUser, newPass] = args.split(',').map(s => s.trim());

    if (!newUser || !newPass) {
      console.log('\nUsage: /adminset username,password\n');
    } else {
      adminCredentials.user = newUser;
      adminCredentials.pass = newPass;
      console.log(`\nAdmin credentials updated:`);
      console.log(`  Username: ${newUser}`);
      console.log(`  Password: ${'*'.repeat(newPass.length)}\n`);
    }
  }
});
