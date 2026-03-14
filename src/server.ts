import express from 'express';
import Database from 'better-sqlite3';
import { unmarshalPublicKey } from '@libp2p/crypto/keys';
import { peerIdFromPublicKey } from './peer-id.js';

const PORT = Number(process.env.PORT ?? 3000);
const DB_PATH = process.env.DB_PATH ?? 'data/peers.db';

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS peers (
    peer_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    created_at TEXT NOT NULL
  );
`);

const insertPeer = db.prepare(
  'INSERT INTO peers (peer_id, username, public_key, created_at) VALUES (?, ?, ?, ?)'
);
const findPeer = db.prepare(
  'SELECT peer_id, username FROM peers WHERE peer_id = ? OR username = ? LIMIT 1'
);
const findPeerByUsername = db.prepare(
  'SELECT peer_id, username FROM peers WHERE username = ? LIMIT 1'
);

const app = express();
app.use(express.json({ limit: '32kb' }));

app.post('/register', async (req, res) => {
  try {
    const { public_key, message, signature } = req.body ?? {};

    if (typeof public_key !== 'string' || typeof message !== 'string' || typeof signature !== 'string') {
      return res.status(400).json({ error: 'public_key, message, and signature are required strings' });
    }

    let payload: { username?: string };
    try {
      payload = JSON.parse(message);
    } catch {
      return res.status(400).json({ error: 'message must be a JSON string containing username' });
    }

    const username = typeof payload.username === 'string' ? payload.username.trim() : '';
    if (!username) {
      return res.status(400).json({ error: 'message.username is required' });
    }

    const publicKeyBytes = Buffer.from(public_key, 'base64');
    const signatureBytes = Buffer.from(signature, 'base64');

    const publicKey = await unmarshalPublicKey(publicKeyBytes);
    const messageBytes = new TextEncoder().encode(message);
    const isValid = await publicKey.verify(messageBytes, signatureBytes);

    if (!isValid) {
      return res.status(401).json({ error: 'invalid signature' });
    }

    const peerId = await peerIdFromPublicKey(publicKeyBytes);
    const existing = findPeer.get(peerId, username);

    if (existing) {
      return res.status(409).json({ error: 'peer_id or username already registered' });
    }

    insertPeer.run(peerId, username, publicKeyBytes, new Date().toISOString());

    return res.status(201).json({ peer_id: peerId, username });
  } catch (error) {
    console.error('register error', error);
    return res.status(500).json({ error: 'internal server error' });
  }
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/find', (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';

  if (!query) {
    return res.status(400).json({ error: 'q query parameter is required' });
  }

  const peer = findPeerByUsername.get(query);

  if (!peer) {
    return res.status(404).json({ error: 'peer not found' });
  }

  return res.json({ peer_id: peer.peer_id, username: peer.username });
});

app.get('/check-availability', (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';

  if (!query) {
    return res.status(400).json({ error: 'q query parameter is required' });
  }

  const peer = findPeerByUsername.get(query);

  return res.json({ available: !peer });
});

app.listen(PORT, () => {
  console.log(`server listening on http://localhost:${PORT}`);
});
