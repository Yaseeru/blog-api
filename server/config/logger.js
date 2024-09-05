const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const { createLogger, format, transports } = winston;
const { combine, timestamp, printf } = format;

// Define custom log format
const logFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} [${level}]: ${message}`;
});

// Create a logger instance
const logger = createLogger({
  level: 'info', // Set default log level
  format: combine(
    timestamp(),
    logFormat
  ),
  transports: [
    new transports.Console(), // Log to the console
    new DailyRotateFile({
      filename: '../logs/app-%DATE%.log', // Log file name with date placeholder
      datePattern: 'YYYY-MM-DD', // Rotate daily, but you can customize this
      maxSize: '20m', // Maximum log file size before rotation
      maxFiles: '14d', // Keep logs for 14 days
      zippedArchive: true, // Compress the archived log files
    })
  ],
});

module.exports = logger;