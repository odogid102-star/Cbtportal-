import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import dotenv from 'dotenv';
import CryptoJS from 'crypto-js';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static('public'));

const API_KEY = process.env.API_KEY || 'Gideon 101*cbt';

// ✅ connect or create SQLite database
const db = await open({
  filename: path.join(__dirname, 'database.db'),
  driver: sqlite3.Database
});

// ✅ create users table if not exists
await db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT,
    lastName TEXT,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password TEXT,
    avatar TEXT,
    createdAt TEXT
  )
`);

// ✅ helper: hash password
function hashPassword(password) {
  return CryptoJS.SHA256(password).toString(CryptoJS.enc.Base64);
}

// ✅ middleware to check API key
function checkApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key !== API_KEY) {
    return res.status(403).json({ message: 'Invalid API key' });
  }
  next();
}

// ✅ REGISTER endpoint
app.post('/api/register', checkApiKey, async (req, res) => {
  const { firstName, lastName, email, username, password, avatar } = req.body;

  if (!firstName || !lastName || !email || !username || !password) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  try {
    const existingUser = await db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    const hashed = hashPassword(password);
    await db.run(
      'INSERT INTO users (firstName, lastName, email, username, password, avatar, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [firstName, lastName, email, username, hashed, avatar || '', new Date().toISOString()]
    );

    res.json({ message: 'Account created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// ✅ LOGIN endpoint
app.post('/api/login', checkApiKey, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Missing username or password' });

  try {
    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const hashed = hashPassword(password);
    if (user.password !== hashed)
      return res.status(401).json({ message: 'Incorrect password' });

    res.json({ message: 'Login successful', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ✅ Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));