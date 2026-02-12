module.exports = {
  apps: [
    {
      name: 'xchat-server',
      script: 'webapp/server.js',
      cwd: '/home/jack/.openclaw/workspace/xchat',
      env: {
        PORT: 3001,
        HTTPS_PORT: 3443,
      },
      log_file: '/tmp/xchat-server.log',
      time: true,
    },
    {
      name: 'xchat-bridge',
      script: 'bridge/tcp-bridge.js',
      cwd: '/home/jack/.openclaw/workspace/xchat',
      env: {
        XCHAT_WALLET_KEY: '4567beadc16233d6d107279a15c64f4da1d71c1668d8e7db6e0ccde0f481ae3f',
        XCHAT_SERVER: 'https://localhost:3443',
        XCHAT_BRIDGE_PORT: 9101,
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
      },
      log_file: '/tmp/xchat-bridge.log',
      time: true,
      // Wait for xchat-server to be ready
      restart_delay: 3000,
    },
  ],
};
