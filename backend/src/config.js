const path = require('node:path');
const ROOT = path.resolve(__dirname, '../..');
const NODE_ENV = process.env.NODE_ENV || 'development';

module.exports = {
  PORT: Number(process.env.PORT || 3000),
  HOST: process.env.HOST || '127.0.0.1',
  DB_PATH: process.env.QU_DB_PATH || path.join(ROOT, 'data', 'qu.sqlite'),
  JWT_SECRET: process.env.QU_JWT_SECRET || 'dev-only-change-this-secret',
  TOKEN_DAYS: Number(process.env.QU_TOKEN_DAYS || 7),
  NODE_ENV,
  PLATFORM_OWNER_EMAIL: process.env.QU_PLATFORM_OWNER_EMAIL || '',
  PLATFORM_OWNER_PASSWORD: process.env.QU_PLATFORM_OWNER_PASSWORD || '',
  TLS_CERT_PATH: process.env.QU_TLS_CERT_PATH || '',
  TLS_KEY_PATH: process.env.QU_TLS_KEY_PATH || '',
  BEHIND_HTTPS_PROXY: process.env.QU_BEHIND_HTTPS_PROXY === 'true',
};
