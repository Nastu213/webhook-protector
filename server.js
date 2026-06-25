'use strict';

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
const PORT    = process.env.PORT    || 3000;
const API_KEY = process.env.API_KEY || '';

if (!API_KEY) {
  console.error('[FATAL] API_KEY environment variable is not set. Exiting.');
  process.exit(1);
}

// Storage — persisted on disk (use Render Disk add-on for true persistence)
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'webhooks.json');

// ─────────────────────────────────────────────────────────────────────────────
// Webhook storage helpers
// ─────────────────────────────────────────────────────────────────────────────
function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (err) {
    console.warn('[WARN] Could not read DB file, starting fresh:', err.message);
  }
  return {};
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('[ERROR] Could not write DB file:', err.message);
  }
}

// In-memory store (seeded from disk on startup)
let db = loadDB();
console.log(`[INFO] Loaded ${Object.keys(db).length} protected webhook(s) from disk.`);

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiter — sliding window, 5 req / 60 s per IP
// ─────────────────────────────────────────────────────────────────────────────
const RATE_LIMIT_MAX    = 5;
const RATE_LIMIT_WINDOW = 60_000; // ms
const ipWindows         = new Map();

// Periodically purge old entries so the Map doesn't grow forever
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW;
  for (const [ip, ts] of ipWindows) {
    const fresh = ts.filter(t => t > cutoff);
    if (fresh.length === 0) ipWindows.delete(ip);
    else ipWindows.set(ip, fresh);
  }
}, 60_000).unref();

function rateLimit(req, res, next) {
  // Support proxied IPs (Render sits behind a load-balancer)
  const ip  = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  const now = Date.now();
  const ts  = (ipWindows.get(ip) || []).filter(t => now - t < RATE_LIMIT_WINDOW);

  if (ts.length >= RATE_LIMIT_MAX) {
    const resetIn = Math.ceil((ts[0] + RATE_LIMIT_WINDOW - now) / 1000);
    res.set('Retry-After', String(resetIn));
    return res.status(429).json({
      error:      'Too Many Requests',
      message:    `Max ${RATE_LIMIT_MAX} requests per minute per IP. Retry in ${resetIn}s.`,
      retryAfter: resetIn,
    });
  }

  ts.push(now);
  ipWindows.set(ip, ts);
  res.set('X-RateLimit-Limit',     String(RATE_LIMIT_MAX));
  res.set('X-RateLimit-Remaining', String(RATE_LIMIT_MAX - ts.length));
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// API key auth (constant-time comparison to prevent timing attacks)
// ─────────────────────────────────────────────────────────────────────────────
function requireApiKey(req, res, next) {
  const provided = req.headers['x-api-key'] || '';
  let valid = false;

  try {
    valid =
      provided.length === API_KEY.length &&
      crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(API_KEY));
  } catch {
    valid = false;
  }

  if (!valid) {
    return res.status(401).json({
      error:   'Unauthorized',
      message: 'Missing or invalid X-API-Key header.',
    });
  }
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// Discord URL validator
// ─────────────────────────────────────────────────────────────────────────────
const DISCORD_PREFIXES = [
  'https://discord.com/api/webhooks/',
  'https://discordapp.com/api/webhooks/',
  'https://ptb.discord.com/api/webhooks/',
  'https://canary.discord.com/api/webhooks/',
];

function isDiscordWebhook(url) {
  return typeof url === 'string' && DISCORD_PREFIXES.some(p => url.startsWith(p));
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload filter
// Only forward messages that contain "🎒 Inventory" OR "🛒 Total Items"
// anywhere in content, embed titles, descriptions, or field values.
// ─────────────────────────────────────────────────────────────────────────────
const ALLOWED_KEYWORDS = ['🎒 Inventory', '🛒 Total Items'];

function payloadMatchesFilter(payload) {
  if (!payload || typeof payload !== 'object') return false;

  // Check top-level content
  const content = payload.content || '';
  if (ALLOWED_KEYWORDS.some(kw => content.includes(kw))) return true;

  // Check embeds
  const embeds = Array.isArray(payload.embeds) ? payload.embeds : [];
  for (const embed of embeds) {
    const parts = [
      embed.title        || '',
      embed.description  || '',
      embed.author?.name || '',
      embed.footer?.text || '',
      ...(Array.isArray(embed.fields)
        ? embed.fields.flatMap(f => [f.name || '', f.value || ''])
        : []),
    ];
    const combined = parts.join(' ');
    if (ALLOWED_KEYWORDS.some(kw => combined.includes(kw))) return true;
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Discord forward helper
// ─────────────────────────────────────────────────────────────────────────────
async function forwardToDiscord(realUrl, payload, query = {}) {
  const url = new URL(realUrl);
  if (query.thread_id) url.searchParams.set('thread_id', query.thread_id);
  if (query.wait)      url.searchParams.set('wait',      query.wait);

  const res = await fetch(url.toString(), {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'WebhookProxy/1.0' },
    body:    JSON.stringify(payload),
  });

  return res;
}

// ─────────────────────────────────────────────────────────────────────────────
// Express app
// ─────────────────────────────────────────────────────────────────────────────
const app = express();

app.set('trust proxy', true); // Render is behind a reverse proxy
app.use(express.json({ limit: '2mb' }));

// Basic security headers
app.use((_, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options',        'DENY');
  res.removeHeader('X-Powered-By');
  next();
});

// ── GET / — Health check ──────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status:   'ok',
    service:  'Discord Webhook Protector Proxy',
    webhooks: Object.keys(db).length,
    uptime:   Math.floor(process.uptime()),
    ts:       new Date().toISOString(),
  });
});

// ── POST /protect — Register a real Discord webhook ───────────────────────────
app.post('/protect', requireApiKey, rateLimit, (req, res) => {
  const { url } = req.body || {};

  if (!url) {
    return res.status(400).json({ error: 'Missing "url" field in request body.' });
  }
  if (!isDiscordWebhook(url)) {
    return res.status(400).json({
      error: 'Invalid URL.',
      message: 'Must be a valid Discord webhook URL (https://discord.com/api/webhooks/...).',
    });
  }

  // Deduplicate: if this real URL is already registered, return existing entry
  const existing = Object.entries(db).find(([, v]) => v.real_url === url);
  if (existing) {
    const [id, meta] = existing;
    const host = `${req.protocol}://${req.get('host')}`;
    return res.json({
      protected_url: `${host}/webhook/${id}`,
      id,
      created_at: meta.created_at,
      message:    'This webhook was already registered. Returning existing protected URL.',
    });
  }

  // Create new protected entry
  const id = crypto.randomBytes(20).toString('hex'); // 40-char hex ID
  db[id] = {
    real_url:   url,         // ← NEVER returned in any response below
    created_at: new Date().toISOString(),
    stats: { forwarded: 0, filtered: 0, errors: 0 },
  };
  saveDB(db);

  const host = `${req.protocol}://${req.get('host')}`;
  console.log(`[INFO] New webhook protected → /webhook/${id}`);

  return res.status(201).json({
    protected_url: `${host}/webhook/${id}`,
    id,
    created_at: db[id].created_at,
    message: 'Webhook registered. Use protected_url instead of the real Discord URL.',
  });
});

// ── GET /webhooks — List registered IDs (no real URLs exposed) ────────────────
app.get('/webhooks', requireApiKey, (req, res) => {
  const host = `${req.protocol}://${req.get('host')}`;
  const list = Object.entries(db).map(([id, meta]) => ({
    id,
    protected_url: `${host}/webhook/${id}`,
    created_at:    meta.created_at,
    stats:         meta.stats,
    // real_url is intentionally omitted
  }));
  res.json({ count: list.length, webhooks: list });
});

// ── DELETE /webhooks/:id — Remove a protected webhook ─────────────────────────
app.delete('/webhooks/:id', requireApiKey, (req, res) => {
  const { id } = req.params;
  if (!db[id]) return res.status(404).json({ error: 'Webhook not found.' });
  delete db[id];
  saveDB(db);
  console.log(`[INFO] Webhook removed: ${id}`);
  res.json({ success: true, message: `Webhook ${id} deleted.` });
});

// ── POST /webhook/:id — Receive payload, filter, forward ─────────────────────
app.post('/webhook/:id', rateLimit, async (req, res) => {
  const { id } = req.params;

  if (!db[id]) {
    return res.status(404).json({ error: 'Protected webhook not found.' });
  }

  const payload = req.body;

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return res.status(400).json({ error: 'Payload must be a JSON object.' });
  }

  // ── Filter check ────────────────────────────────────────────────────────────
  if (!payloadMatchesFilter(payload)) {
    db[id].stats.filtered++;
    saveDB(db);
    console.log(`[FILTER] /webhook/${id} → dropped (no matching keyword)`);
    return res.status(200).json({
      success:   true,
      forwarded: false,
      reason:    'Payload does not contain any allowed keyword (🎒 Inventory | 🛒 Total Items).',
    });
  }

  // ── Forward to real Discord webhook ────────────────────────────────────────
  const realUrl = db[id].real_url;

  let discordRes;
  try {
    discordRes = await forwardToDiscord(realUrl, payload, req.query);
  } catch (err) {
    db[id].stats.errors++;
    saveDB(db);
    console.error(`[ERROR] /webhook/${id} → Could not reach Discord: ${err.message}`);
    return res.status(502).json({
      error:   'Bad Gateway',
      message: 'Could not reach Discord. Try again later.',
    });
  }

  // Discord rate-limit pass-through
  if (discordRes.status === 429) {
    const retryAfter = discordRes.headers.get('retry-after') || '5';
    db[id].stats.errors++;
    saveDB(db);
    return res.status(429).json({
      error:      'Discord Rate Limited',
      message:    `Discord is throttling this webhook. Retry after ${retryAfter}s.`,
      retryAfter: parseFloat(retryAfter),
    });
  }

  // Other Discord errors
  if (!discordRes.ok) {
    let errBody = null;
    try { errBody = await discordRes.json(); } catch { /* ignore */ }
    db[id].stats.errors++;
    saveDB(db);
    console.warn(`[WARN] /webhook/${id} → Discord ${discordRes.status}`, errBody);
    return res.status(discordRes.status >= 500 ? 502 : 400).json({
      error:   'Discord Error',
      message: errBody?.message || `Discord returned HTTP ${discordRes.status}`,
      code:    errBody?.code,
    });
  }

  // Success
  db[id].stats.forwarded++;
  saveDB(db);
  console.log(`[OK] /webhook/${id} → forwarded to Discord (HTTP ${discordRes.status})`);

  // If Discord sent a message body (wait=true mode), relay it
  if (discordRes.status !== 204) {
    try {
      const data = await discordRes.json();
      return res.status(200).json(data);
    } catch { /* fall through */ }
  }

  return res.status(204).send();
});

// ── 404 fallback ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: `${req.method} ${req.path}` });
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[ERROR] Unhandled:', err.message);
  if (!res.headersSent) res.status(500).json({ error: 'Internal Server Error' });
});

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] 🚀 Webhook proxy running on port ${PORT}`);
  console.log(`  → Health  : GET  /`);
  console.log(`  → Protect : POST /protect   (X-API-Key required)`);
  console.log(`  → List    : GET  /webhooks  (X-API-Key required)`);
  console.log(`  → Delete  : DEL  /webhooks/:id (X-API-Key required)`);
  console.log(`  → Forward : POST /webhook/:id`);
  console.log(`  → DB file : ${DB_PATH}`);
});
