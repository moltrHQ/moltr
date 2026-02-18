// PM2 Konfiguration fuer Moltr Security API
// Start: pm2 start ecosystem.config.cjs
// Status: pm2 status
// Logs: pm2 logs moltr-security
// Stop: pm2 stop moltr-security

const path = require("path");

module.exports = {
  apps: [
    {
      name: "moltr-security",
      script: "python",
      args: "-m uvicorn src.api.server:app --host 0.0.0.0 --port 8420 --log-level info",
      cwd: __dirname,
      interpreter: "none",
      autorestart: true,
      max_restarts: 10,
      restart_delay: 3000,
      error_file: path.join(__dirname, "logs", "moltr-error.log"),
      out_file: path.join(__dirname, "logs", "moltr-api.log"),
      log_date_format: "YYYY-MM-DD HH:mm:ss",
      watch: false,
      max_memory_restart: "300M",
    },
  ],
};
