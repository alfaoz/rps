module.exports = {
  apps: [{
    name: 'rps-beta',
    script: 'server.js',
    cwd: '/root/rps-beta',
    env: {
      PORT: 3001,
      ADMIN_USER: 'beta-admin',
      ADMIN_PASS: 'beta2024'
    }
  }]
};
