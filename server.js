'use strict';

const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
const VERSION = packageJson.version;
const API_KEY = process.env.API_KEY || crypto.randomBytes(32).toString('hex');

if (NODE_ENV === 'development') console.log('🔑 API Key:', API_KEY);
console.log('📦 Version:', VERSION);
console.log('🔐 Umgebung:', NODE_ENV);

const CHANGELOG = JSON.parse(fs.readFileSync(path.join(__dirname, 'changelog.json'), 'utf8'));

const CATEGORIES = [
    'Internet', 'Mobilfunk', 'Streaming', 'Versicherung',
    'Strom/Gas', 'Miete', 'Fitness', 'Abonnement',
    'Cloud/Software', 'Verein', 'Leasing',
    'Kredit', 'Wartung', 'Sonstiges'
];

const BILLING_INTERVALS = {
    monthly: { factor: 1, label: 'Monatlich' },
    quarterly: { factor: 3, label: 'Quartalsweise' },
    'semi-annual': { factor: 6, label: 'Halbjährlich' },
    annual: { factor: 12, label: 'Jährlich' }
};

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(express.json({ limit: '1mb' }));

// Security headers
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' https://unpkg.com 'unsafe-inline' 'unsafe-eval'",
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
        "font-src 'self' https://fonts.gstatic.com",
        "connect-src 'self'",
        "img-src 'self' data:",
    ].join('; '));
    next();
});

// Serve static files BUT NOT index.html (that's served dynamically with injected config)
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// API Key + Origin validation middleware
function validateApiKey(req, res, next) {
    const key = req.headers['x-api-key'] || req.query.api_key;
    if (key !== API_KEY) {
        return res.status(401).json({ error: 'Nicht autorisiert' });
    }

    // Origin/Referer check on state-changing requests (blocks bare curl POST/PUT/DELETE)
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        const origin = req.headers.origin;
        const referer = req.headers.referer;
        if (!origin && !referer) {
            return res.status(403).json({ error: 'Zugriff verweigert – Origin fehlt' });
        }
    }

    next();
}

// Session validation middleware (checks x-session-token header or session_token query param)
function validateSession(req, res, next) {
    const token = req.headers['x-session-token'] || req.query.session_token;
    if (!token) return res.status(401).json({ error: 'Sitzung fehlt' });

    const row = stmts.verifySession.get(token);
    if (!row) return res.status(401).json({ error: 'Sitzung abgelaufen' });

    req.sessionUser = row.name;
    req.sessionUserId = row.id;
    next();
}

// ============================================================================
// RATE LIMITING (in-memory, per IP)
// ============================================================================

const rateLimitMap = new Map();

function rateLimit(maxAttempts = 10, windowMs = 15 * 60 * 1000) {
    return (req, res, next) => {
        const ip = req.ip || req.socket.remoteAddress;
        const now = Date.now();
        const entry = rateLimitMap.get(ip);

        if (entry && (now - entry.firstAttempt) > windowMs) {
            rateLimitMap.delete(ip);
        }

        const current = rateLimitMap.get(ip);
        if (current && current.count >= maxAttempts) {
            const retryAfter = Math.ceil((current.firstAttempt + windowMs - now) / 1000);
            res.setHeader('Retry-After', retryAfter);
            return res.status(429).json({ error: 'Zu viele Versuche – bitte später erneut versuchen' });
        }

        if (current) {
            current.count++;
        } else {
            rateLimitMap.set(ip, { count: 1, firstAttempt: now });
        }

        req.rateLimitReset = () => rateLimitMap.delete(ip);
        next();
    };
}

const authLimiter = rateLimit();

// Cleanup expired rate limit entries every 15 minutes
setInterval(() => {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    for (const [ip, entry] of rateLimitMap) {
        if ((now - entry.firstAttempt) > windowMs) rateLimitMap.delete(ip);
    }
}, 15 * 60 * 1000).unref();

// ============================================================================
// VALIDATION
// ============================================================================

function validateUser(name) {
    if (typeof name !== 'string') return 'Benutzername ungültig';
    const trimmed = name.trim();
    if (trimmed.length < 1 || trimmed.length > 50) return 'Benutzername: 1-50 Zeichen';
    if (/[<>"'`;\\\/\x00-\x1f]/.test(trimmed)) return 'Benutzername enthält ungültige Zeichen';
    return null;
}

function validatePassword(pw) {
    if (typeof pw !== 'string') return 'Passwort ungültig';
    if (pw.length < 4) return 'Passwort: mindestens 4 Zeichen';
    if (pw.length > 128) return 'Passwort: maximal 128 Zeichen';
    return null;
}

function hashPassword(pw) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
    return { hash, salt };
}

function verifyPassword(pw, hash, salt) {
    const derived = crypto.scryptSync(pw, salt, 64);
    const expected = Buffer.from(hash, 'hex');
    return crypto.timingSafeEqual(derived, expected);
}

function generateSessionToken() {
    return crypto.randomBytes(64).toString('hex');
}

function sanitizeFilename(name) {
    return name.replace(/[^a-zA-Z0-9äöüÄÖÜß_-]/g, '_');
}

function calculateMonthlyCost(cost, billing_interval) {
    const interval = BILLING_INTERVALS[billing_interval];
    if (!interval) return cost;
    return Math.round((cost / interval.factor) * 100) / 100;
}

const VALID_STATUSES = ['active', 'cancelled', 'expired'];

function validateContract(body) {
    const { name, category, start_date, duration_months, cancellation_period_months, cost,
            billing_interval, cashback, description, notes, status } = body;
    if (!name || typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 200)
        return 'Name: 1-200 Zeichen';
    if (!category || !CATEGORIES.includes(category))
        return 'Ungültige Kategorie';
    if (!start_date || !/^\d{4}-\d{2}-\d{2}$/.test(start_date) || isNaN(Date.parse(start_date)))
        return 'Ungültiges Startdatum (YYYY-MM-DD)';
    if (!Number.isInteger(duration_months) || duration_months < 1 || duration_months > 600)
        return 'Laufzeit: 1-600 Monate';
    if (!Number.isInteger(cancellation_period_months) || cancellation_period_months < 0 || cancellation_period_months > 24)
        return 'Kündigungsfrist: 0-24 Monate';
    if (typeof cost !== 'number' || !Number.isFinite(cost) || cost < 0 || cost > 99999)
        return 'Kosten: 0-99999 EUR';
    if (billing_interval !== undefined && billing_interval !== null && !BILLING_INTERVALS[billing_interval])
        return 'Ungültiges Zahlungsintervall';
    if (cashback !== undefined && cashback !== null && (typeof cashback !== 'string' || cashback.length > 200))
        return 'Cashback: maximal 200 Zeichen';
    if (description !== undefined && description !== null && (typeof description !== 'string' || description.length > 2000))
        return 'Beschreibung: maximal 2000 Zeichen';
    if (notes !== undefined && notes !== null && (typeof notes !== 'string' || notes.length > 2000))
        return 'Notizen: maximal 2000 Zeichen';
    if (status !== undefined && status !== null && !VALID_STATUSES.includes(status))
        return 'Status: active, cancelled oder expired';
    if (body.split_count !== undefined && (!Number.isInteger(body.split_count) || body.split_count < 1 || body.split_count > 20))
        return 'Geteilt mit: 1-20 Personen';
    if (body.cancel_warn_days !== undefined && body.cancel_warn_days !== null && (!Number.isInteger(body.cancel_warn_days) || body.cancel_warn_days < 1 || body.cancel_warn_days > 365))
        return 'Kündigungswarnung: 1-365 Tage';
    if (body.cancelled_at !== undefined && body.cancelled_at !== null &&
        (typeof body.cancelled_at !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(body.cancelled_at) || isNaN(Date.parse(body.cancelled_at))))
        return 'Kündigungsdatum: ungültiges Format (YYYY-MM-DD)';
    if (body.customer_number !== undefined && body.customer_number !== null &&
        (typeof body.customer_number !== 'string' || body.customer_number.length > 100))
        return 'Kundennummer: maximal 100 Zeichen';
    if (body.contract_number !== undefined && body.contract_number !== null &&
        (typeof body.contract_number !== 'string' || body.contract_number.length > 100))
        return 'Vertragsnummer: maximal 100 Zeichen';
    if (body.cancellation_date_override !== undefined && body.cancellation_date_override !== null &&
        (typeof body.cancellation_date_override !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(body.cancellation_date_override) || isNaN(Date.parse(body.cancellation_date_override))))
        return 'Kündigungsdatum (manuell): ungültiges Format (YYYY-MM-DD)';
    return null;
}

function calculateDates(start_date, duration_months, cancellation_period_months, auto_renew) {
    // Use UTC methods throughout to avoid timezone-related off-by-one errors
    const [y, m, d] = start_date.split('-').map(Number);
    const now = new Date();
    let end = new Date(Date.UTC(y, m - 1 + duration_months, d));

    if (auto_renew) {
        while (end <= now) {
            end.setUTCMonth(end.getUTCMonth() + duration_months);
        }
    }

    const cancellation = new Date(end);
    cancellation.setUTCMonth(cancellation.getUTCMonth() - cancellation_period_months);

    const fmt = dt => dt.toISOString().split('T')[0];
    return { end_date: fmt(end), cancellation_date: fmt(cancellation) };
}

// ============================================================================
// DATABASE (better-sqlite3 — synchronous, fast, safe)
// ============================================================================

const DB_PATH = process.env.DB_PATH || './data/contracts.db';
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        salt TEXT,
        session_token TEXT,
        session_expires TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS contracts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        start_date TEXT NOT NULL,
        duration_months INTEGER NOT NULL,
        cancellation_period_months INTEGER NOT NULL DEFAULT 3,
        cancellation_date TEXT,
        end_date TEXT,
        cost REAL NOT NULL DEFAULT 0,
        billing_interval TEXT DEFAULT 'monthly',
        monthly_cost REAL NOT NULL DEFAULT 0,
        cashback TEXT,
        description TEXT,
        status TEXT DEFAULT 'active',
        auto_renew INTEGER DEFAULT 1,
        notify INTEGER DEFAULT 1,
        split_count INTEGER DEFAULT 1,
        cancel_warn_days INTEGER DEFAULT 90,
        cancelled_at TEXT,
        cancellation_confirmed INTEGER DEFAULT 0,
        customer_number TEXT,
        contract_number TEXT,
        cancellation_date_override TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_contracts_user ON contracts(user_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(user_id, status)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_contracts_cancel ON contracts(user_id, cancellation_date)`);

console.log('✓ Datenbank initialisiert (better-sqlite3, WAL-Modus)');

// Migration: Add new v1.1 columns if missing
const cols = db.prepare("PRAGMA table_info(contracts)").all().map(c => c.name);
if (!cols.includes('cost')) {
    db.exec("ALTER TABLE contracts ADD COLUMN cost REAL NOT NULL DEFAULT 0");
    db.exec("UPDATE contracts SET cost = monthly_cost");
}
if (!cols.includes('billing_interval')) {
    db.exec("ALTER TABLE contracts ADD COLUMN billing_interval TEXT DEFAULT 'monthly'");
}
if (!cols.includes('cashback')) {
    db.exec("ALTER TABLE contracts ADD COLUMN cashback TEXT");
}
if (!cols.includes('notify')) {
    db.exec("ALTER TABLE contracts ADD COLUMN notify INTEGER DEFAULT 1");
}
if (!cols.includes('split_count')) {
    db.exec("ALTER TABLE contracts ADD COLUMN split_count INTEGER DEFAULT 1");
}
if (!cols.includes('cancel_warn_days')) {
    db.exec("ALTER TABLE contracts ADD COLUMN cancel_warn_days INTEGER DEFAULT 90");
}
if (!cols.includes('cancelled_at')) {
    db.exec("ALTER TABLE contracts ADD COLUMN cancelled_at TEXT");
}
if (!cols.includes('cancellation_confirmed')) {
    db.exec("ALTER TABLE contracts ADD COLUMN cancellation_confirmed INTEGER DEFAULT 0");
}
if (!cols.includes('customer_number')) {
    db.exec("ALTER TABLE contracts ADD COLUMN customer_number TEXT");
}
if (!cols.includes('contract_number')) {
    db.exec("ALTER TABLE contracts ADD COLUMN contract_number TEXT");
}
if (!cols.includes('cancellation_date_override')) {
    db.exec("ALTER TABLE contracts ADD COLUMN cancellation_date_override TEXT");
}

// ============================================================================
// PREPARED STATEMENTS
// ============================================================================

const stmts = {
    // Users
    getUsers: db.prepare('SELECT id, name, CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END AS hasPassword FROM users ORDER BY name'),
    getUser: db.prepare('SELECT id, name, password_hash, salt FROM users WHERE name = ?'),
    getUserById: db.prepare('SELECT id, name FROM users WHERE id = ?'),
    insertUser: db.prepare('INSERT INTO users (name, password_hash, salt) VALUES (?, ?, ?)'),
    deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
    setPassword: db.prepare("UPDATE users SET password_hash = ?, salt = ? WHERE name = ? AND password_hash IS NULL"),
    setSession: db.prepare('UPDATE users SET session_token = ?, session_expires = ? WHERE name = ?'),
    verifySession: db.prepare("SELECT id, name FROM users WHERE session_token = ? AND session_expires > datetime('now')"),
    clearSession: db.prepare('UPDATE users SET session_token = NULL, session_expires = NULL WHERE name = ?'),

    // Contracts
    getContracts: db.prepare('SELECT * FROM contracts WHERE user_id = ? ORDER BY cancellation_date ASC'),
    getContract: db.prepare('SELECT * FROM contracts WHERE id = ? AND user_id = ?'),
    insertContract: db.prepare(`
        INSERT INTO contracts (user_id, name, category, start_date, duration_months,
            cancellation_period_months, cancellation_date, end_date, cost, billing_interval,
            monthly_cost, cashback, description, status, auto_renew, notify, split_count,
            cancel_warn_days, cancelled_at, cancellation_confirmed, customer_number, contract_number,
            cancellation_date_override, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `),
    updateContract: db.prepare(`
        UPDATE contracts SET name=?, category=?, start_date=?, duration_months=?,
            cancellation_period_months=?, cancellation_date=?, end_date=?, cost=?,
            billing_interval=?, monthly_cost=?, cashback=?, description=?, status=?,
            auto_renew=?, notify=?, split_count=?, cancel_warn_days=?,
            cancelled_at=?, cancellation_confirmed=?, customer_number=?, contract_number=?,
            cancellation_date_override=?, notes=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND user_id=?
    `),
    deleteContract: db.prepare('DELETE FROM contracts WHERE id = ? AND user_id = ?'),
    deleteUserContracts: db.prepare('DELETE FROM contracts WHERE user_id = ?'),
    getStats: db.prepare(`
        SELECT category,
            COUNT(*) as count,
            SUM(monthly_cost) as monthly_total,
            SUM(monthly_cost * 12) as yearly_total,
            SUM(monthly_cost / COALESCE(NULLIF(split_count, 0), 1)) as monthly_effective,
            SUM(monthly_cost * 12 / COALESCE(NULLIF(split_count, 0), 1)) as yearly_effective
        FROM contracts WHERE user_id = ? AND status = 'active'
        GROUP BY category ORDER BY monthly_total DESC
    `),
    exportContracts: db.prepare('SELECT * FROM contracts WHERE user_id = ? ORDER BY name')
};

// ============================================================================
// SESSION HELPER
// ============================================================================

function createSession(userName) {
    const token = generateSessionToken();
    const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    stmts.setSession.run(token, expires, userName);
    return token;
}

// ============================================================================
// PAGE ROUTE — index.html with injected config (API key + environment)
// ============================================================================

function escapeForJS(str) {
    return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"')
              .replace(/</g, '\\x3c').replace(/>/g, '\\x3e').replace(/&/g, '\\x26');
}

app.get('/', (_req, res) => {
    try {
        let html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
        html = html.replace('%%API_KEY%%', escapeForJS(API_KEY));
        html = html.replace('%%NODE_ENV%%', escapeForJS(NODE_ENV));
        res.type('html').send(html);
    } catch (error) {
        console.error('index.html Fehler:', error);
        res.status(500).send('Server-Fehler');
    }
});

// ============================================================================
// PUBLIC ENDPOINTS (no auth needed)
// ============================================================================

app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString(), version: VERSION, environment: NODE_ENV });
});

app.get('/api/version', (_req, res) => {
    res.json({ version: VERSION });
});

app.get('/api/changelog', (_req, res) => {
    res.json(CHANGELOG);
});

app.get('/api/categories', (_req, res) => {
    res.json(CATEGORIES);
});

app.get('/api/billing-intervals', (_req, res) => {
    res.json(BILLING_INTERVALS);
});

// ============================================================================
// AUTH ENDPOINTS
// ============================================================================

// Login
app.post('/api/auth/login', validateApiKey, authLimiter, (req, res) => {
    try {
        const { user, password } = req.body || {};
        const userErr = validateUser(user);
        if (userErr) return res.status(400).json({ error: userErr });

        const row = stmts.getUser.get(user);
        if (!row) return res.status(404).json({ error: 'Benutzer nicht gefunden' });

        if (!row.password_hash) {
            return res.json({ success: false, needsPassword: true });
        }

        if (!password || !verifyPassword(password, row.password_hash, row.salt)) {
            return res.status(401).json({ error: 'Falsches Passwort' });
        }

        req.rateLimitReset();
        const token = createSession(user);
        res.json({ success: true, token });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Anmeldefehler' });
    }
});

// Set password (first time only — for migrated users without password)
app.post('/api/auth/set-password', validateApiKey, authLimiter, (req, res) => {
    try {
        const { user, password } = req.body || {};
        const userErr = validateUser(user);
        if (userErr) return res.status(400).json({ error: userErr });
        const pwErr = validatePassword(password);
        if (pwErr) return res.status(400).json({ error: pwErr });

        const row = stmts.getUser.get(user);
        if (!row) return res.status(404).json({ error: 'Benutzer nicht gefunden' });
        if (row.password_hash) return res.status(400).json({ error: 'Passwort bereits gesetzt' });

        const { hash, salt } = hashPassword(password);
        const result = stmts.setPassword.run(hash, salt, user);
        if (result.changes === 0) return res.status(400).json({ error: 'Passwort konnte nicht gesetzt werden' });

        req.rateLimitReset();
        const token = createSession(user);
        res.json({ success: true, token });
    } catch (error) {
        console.error('Set password error:', error.message);
        res.status(500).json({ error: 'Fehler beim Setzen des Passworts' });
    }
});

// Verify session token
app.post('/api/auth/verify', validateApiKey, (req, res) => {
    try {
        const { token } = req.body || {};
        if (!token || typeof token !== 'string') return res.status(401).json({ error: 'Token fehlt' });

        const row = stmts.verifySession.get(token);
        if (!row) return res.status(401).json({ error: 'Sitzung abgelaufen' });

        res.json({ success: true, user: row.name, userId: row.id });
    } catch (error) {
        console.error('Verify session error:', error.message);
        res.status(500).json({ error: 'Verifizierungsfehler' });
    }
});

// Logout (clear session)
app.post('/api/auth/logout', validateApiKey, (req, res) => {
    try {
        const { token } = req.body || {};
        if (token) {
            const row = stmts.verifySession.get(token);
            if (row) stmts.clearSession.run(row.name);
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Logout error:', error.message);
        res.status(500).json({ error: 'Abmeldefehler' });
    }
});

// ============================================================================
// USER ENDPOINTS
// ============================================================================

// Get all users (with hasPassword flag)
app.get('/api/users', validateApiKey, (req, res) => {
    try {
        const rows = stmts.getUsers.all();
        res.json(rows.map(row => ({ id: row.id, name: row.name, hasPassword: !!row.hasPassword })));
    } catch (error) {
        console.error('Fetch users error:', error.message);
        res.status(500).json({ error: 'Fehler beim Laden' });
    }
});

// Register new user (with password)
app.post('/api/users/:user', validateApiKey, authLimiter, (req, res) => {
    try {
        const err = validateUser(req.params.user);
        if (err) return res.status(400).json({ error: err });
        const { password } = req.body || {};
        const pwErr = validatePassword(password);
        if (pwErr) return res.status(400).json({ error: pwErr });

        const existing = stmts.getUser.get(req.params.user);
        if (existing) return res.status(409).json({ error: 'Benutzer existiert bereits' });

        const { hash, salt } = hashPassword(password);
        stmts.insertUser.run(req.params.user, hash, salt);
        req.rateLimitReset();
        const token = createSession(req.params.user);
        res.json({ success: true, user: req.params.user, token });
    } catch (error) {
        console.error('Register user error:', error.message);
        res.status(500).json({ error: 'Fehler beim Erstellen' });
    }
});

// Delete user and all their contracts
app.delete('/api/users/:user', validateApiKey, validateSession, (req, res) => {
    try {
        const err = validateUser(req.params.user);
        if (err) return res.status(400).json({ error: err });

        // Check that the session user matches the user being deleted
        if (req.params.user !== req.sessionUser) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        stmts.clearSession.run(req.params.user);
        stmts.deleteUserContracts.run(req.sessionUserId);
        stmts.deleteUser.run(req.sessionUserId);
        res.json({ success: true, user: req.params.user });
    } catch (error) {
        console.error('Delete user error:', error.message);
        res.status(500).json({ error: 'Fehler beim Löschen' });
    }
});

// ============================================================================
// CONTRACT CRUD ENDPOINTS
// ============================================================================

// Get all contracts for session user
app.get('/api/contracts', validateApiKey, validateSession, (req, res) => {
    try {
        const rows = stmts.getContracts.all(req.sessionUserId);

        // Recalculate dates for auto_renew active contracts (unless manually overridden)
        const contracts = rows.map(row => {
            if (row.auto_renew && row.status === 'active') {
                const dates = calculateDates(row.start_date, row.duration_months, row.cancellation_period_months, true);
                return { ...row, end_date: dates.end_date, cancellation_date: row.cancellation_date_override || dates.cancellation_date };
            }
            return row;
        });

        res.json(contracts);
    } catch (error) {
        console.error('Fetch contracts error:', error.message);
        res.status(500).json({ error: 'Fehler beim Laden' });
    }
});

// Get contract statistics — MUST be before /api/contracts/:id
app.get('/api/contracts/stats', validateApiKey, validateSession, (req, res) => {
    try {
        const categories = stmts.getStats.all(req.sessionUserId);
        const totalMonthly = categories.reduce((sum, c) => sum + (c.monthly_total || 0), 0);
        const totalYearly = categories.reduce((sum, c) => sum + (c.yearly_total || 0), 0);
        const totalMonthlyEffective = Math.round(categories.reduce((sum, c) => sum + (c.monthly_effective || 0), 0) * 100) / 100;
        const totalYearlyEffective = Math.round(categories.reduce((sum, c) => sum + (c.yearly_effective || 0), 0) * 100) / 100;
        res.json({ categories, totalMonthly, totalYearly, totalMonthlyEffective, totalYearlyEffective });
    } catch (error) {
        console.error('Fetch stats error:', error.message);
        res.status(500).json({ error: 'Fehler beim Laden der Statistiken' });
    }
});

// Get single contract by id
app.get('/api/contracts/:id', validateApiKey, validateSession, (req, res) => {
    try {
        const contract = stmts.getContract.get(req.params.id, req.sessionUserId);
        if (!contract) return res.status(404).json({ error: 'Vertrag nicht gefunden' });
        res.json(contract);
    } catch (error) {
        console.error('Fetch contract error:', error.message);
        res.status(500).json({ error: 'Fehler beim Laden' });
    }
});

// Create new contract
app.post('/api/contracts', validateApiKey, validateSession, (req, res) => {
    try {
        const validationErr = validateContract(req.body);
        if (validationErr) return res.status(400).json({ error: validationErr });

        const { name, category, start_date, duration_months, cancellation_period_months, cost,
                billing_interval, cashback, description, status, auto_renew, notify, split_count,
                cancel_warn_days, cancelled_at, cancellation_confirmed, customer_number, contract_number,
                cancellation_date_override, notes } = req.body;

        const autoRenew = auto_renew !== undefined ? (auto_renew ? 1 : 0) : 1;
        const notifyFlag = notify !== undefined ? (notify ? 1 : 0) : 1;
        const splitCount = split_count !== undefined ? split_count : 1;
        const warnDays = cancel_warn_days !== undefined ? cancel_warn_days : 90;
        const cancelledAt = cancelled_at || null;
        const cancelConfirmed = cancellation_confirmed ? 1 : 0;
        const customerNumber = customer_number || null;
        const contractNumber = contract_number || null;
        const cancelOverride = cancellation_date_override || null;
        const interval = billing_interval || 'monthly';
        const monthlyCost = calculateMonthlyCost(cost, interval);
        const contractStatus = status || 'active';
        const dates = calculateDates(start_date, duration_months, cancellation_period_months, autoRenew);
        const finalCancelDate = cancelOverride || dates.cancellation_date;

        const result = stmts.insertContract.run(
            req.sessionUserId,
            name.trim(),
            category,
            start_date,
            duration_months,
            cancellation_period_months,
            finalCancelDate,
            dates.end_date,
            cost,
            interval,
            monthlyCost,
            cashback || null,
            description || null,
            contractStatus,
            autoRenew,
            notifyFlag,
            splitCount,
            warnDays,
            cancelledAt,
            cancelConfirmed,
            customerNumber,
            contractNumber,
            cancelOverride,
            notes || null
        );

        res.json({ success: true, id: Number(result.lastInsertRowid) });
    } catch (error) {
        console.error('Create contract error:', error.message);
        res.status(500).json({ error: 'Fehler beim Erstellen' });
    }
});

// Update contract
app.put('/api/contracts/:id', validateApiKey, validateSession, (req, res) => {
    try {
        const existing = stmts.getContract.get(req.params.id, req.sessionUserId);
        if (!existing) return res.status(404).json({ error: 'Vertrag nicht gefunden' });

        const validationErr = validateContract(req.body);
        if (validationErr) return res.status(400).json({ error: validationErr });

        const { name, category, start_date, duration_months, cancellation_period_months, cost,
                billing_interval, cashback, description, status, auto_renew, notify, split_count,
                cancel_warn_days, cancelled_at, cancellation_confirmed, customer_number, contract_number,
                cancellation_date_override, notes } = req.body;

        const autoRenew = auto_renew !== undefined ? (auto_renew ? 1 : 0) : 1;
        const notifyFlag = notify !== undefined ? (notify ? 1 : 0) : 1;
        const splitCount = split_count !== undefined ? split_count : 1;
        const warnDays = cancel_warn_days !== undefined ? cancel_warn_days : 90;
        const cancelledAt = cancelled_at || null;
        const cancelConfirmed = cancellation_confirmed ? 1 : 0;
        const customerNumber = customer_number || null;
        const contractNumber = contract_number || null;
        const cancelOverride = cancellation_date_override || null;
        const interval = billing_interval || 'monthly';
        const monthlyCost = calculateMonthlyCost(cost, interval);
        const contractStatus = status || 'active';
        const dates = calculateDates(start_date, duration_months, cancellation_period_months, autoRenew);
        const finalCancelDate = cancelOverride || dates.cancellation_date;

        const result = stmts.updateContract.run(
            name.trim(),
            category,
            start_date,
            duration_months,
            cancellation_period_months,
            finalCancelDate,
            dates.end_date,
            cost,
            interval,
            monthlyCost,
            cashback || null,
            description || null,
            contractStatus,
            autoRenew,
            notifyFlag,
            splitCount,
            warnDays,
            cancelledAt,
            cancelConfirmed,
            customerNumber,
            contractNumber,
            cancelOverride,
            notes || null,
            req.params.id,
            req.sessionUserId
        );

        res.json({ success: true, changes: result.changes });
    } catch (error) {
        console.error('Update contract error:', error.message);
        res.status(500).json({ error: 'Fehler beim Aktualisieren' });
    }
});

// Delete contract
app.delete('/api/contracts/:id', validateApiKey, validateSession, (req, res) => {
    try {
        const result = stmts.deleteContract.run(req.params.id, req.sessionUserId);
        if (result.changes === 0) return res.status(404).json({ error: 'Vertrag nicht gefunden' });
        res.json({ success: true, deleted: result.changes });
    } catch (error) {
        console.error('Delete contract error:', error.message);
        res.status(500).json({ error: 'Fehler beim Löschen' });
    }
});

// ============================================================================
// EXPORT
// ============================================================================

// JSON Export (direct download via api_key + session_token in query)
app.get('/api/export/json', validateApiKey, validateSession, (req, res) => {
    try {
        const rows = stmts.exportContracts.all(req.sessionUserId);
        const safeName = sanitizeFilename(req.sessionUser);
        const filename = `vertraege-${safeName}-${new Date().toISOString().split('T')[0]}.json`;
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.json(rows);
    } catch (error) {
        console.error('JSON-Export:', error.message);
        res.status(500).json({ error: 'Export fehlgeschlagen' });
    }
});

// CSV Export (Excel-kompatibel, BOM für Umlaute)
app.get('/api/export/csv', validateApiKey, validateSession, (req, res) => {
    try {
        const rows = stmts.exportContracts.all(req.sessionUserId);
        const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const header = 'Name;Kategorie;Startdatum;Laufzeit (Monate);Kündigungsfrist (Monate);Kündigungsdatum;Enddatum;Kosten;Zahlungsintervall;Monatliche Kosten;Cashback;Geteilt mit;Beschreibung;Status;Auto-Verlängerung;Kündigungswarnung;Warnzeitraum (Tage);Gekündigt am;Kündigung bestätigt;Kundennummer;Vertragsnummer;Notizen\n';
        const body = rows.map(r =>
            [esc(r.name), esc(r.category), r.start_date, r.duration_months,
             r.cancellation_period_months, r.cancellation_date, r.end_date,
             String(r.cost).replace('.', ','),
             (BILLING_INTERVALS[r.billing_interval] || BILLING_INTERVALS.monthly).label,
             String(r.monthly_cost).replace('.', ','),
             esc(r.cashback),
             r.split_count || 1,
             esc(r.description), esc(r.status),
             r.auto_renew ? 'Ja' : 'Nein',
             r.notify ? 'Ja' : 'Nein',
             r.cancel_warn_days || 90,
             esc(r.cancelled_at),
             r.cancellation_confirmed ? 'Ja' : 'Nein',
             esc(r.customer_number),
             esc(r.contract_number),
             esc(r.notes)].join(';')
        ).join('\n');
        const safeName = sanitizeFilename(req.sessionUser);
        const filename = `vertraege-${safeName}-${new Date().toISOString().split('T')[0]}.csv`;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send('\uFEFF' + header + body);
    } catch (error) {
        console.error('CSV-Export:', error.message);
        res.status(500).json({ error: 'CSV-Export fehlgeschlagen' });
    }
});

// ============================================================================
// IMPORT
// ============================================================================

const importContracts = db.transaction((userId, contracts) => {
    let count = 0;
    for (const c of contracts) {
        if (c.cost === undefined && c.monthly_cost !== undefined) { c.cost = c.monthly_cost; }

        const validationErr = validateContract(c);
        if (validationErr) continue;

        const autoRenew = c.auto_renew !== undefined ? (c.auto_renew ? 1 : 0) : 1;
        const notifyFlag = c.notify !== undefined ? (c.notify ? 1 : 0) : 1;
        const splitCount = c.split_count !== undefined ? c.split_count : 1;
        const warnDays = c.cancel_warn_days !== undefined ? c.cancel_warn_days : 90;
        const cancelledAt = c.cancelled_at || null;
        const cancelConfirmed = c.cancellation_confirmed ? 1 : 0;
        const customerNumber = c.customer_number || null;
        const contractNumber = c.contract_number || null;
        const cancelOverride = c.cancellation_date_override || null;
        const interval = c.billing_interval || 'monthly';
        const monthlyCost = calculateMonthlyCost(c.cost, interval);
        const contractStatus = c.status || 'active';
        const dates = calculateDates(c.start_date, c.duration_months, c.cancellation_period_months, autoRenew);
        const finalCancelDate = cancelOverride || dates.cancellation_date;

        stmts.insertContract.run(
            userId,
            c.name.trim(),
            c.category,
            c.start_date,
            c.duration_months,
            c.cancellation_period_months,
            finalCancelDate,
            dates.end_date,
            c.cost,
            interval,
            monthlyCost,
            c.cashback || null,
            c.description || null,
            contractStatus,
            autoRenew,
            notifyFlag,
            splitCount,
            warnDays,
            cancelledAt,
            cancelConfirmed,
            customerNumber,
            contractNumber,
            cancelOverride,
            c.notes || null
        );
        count++;
    }
    return count;
});

app.post('/api/import/json', validateApiKey, validateSession, (req, res) => {
    try {
        const data = req.body.data;
        if (!Array.isArray(data)) {
            return res.status(400).json({ error: 'data muss ein Array sein' });
        }
        if (data.length === 0) return res.status(400).json({ error: 'Keine Daten zum Importieren' });
        if (data.length > 1000) return res.status(400).json({ error: 'Maximal 1.000 Verträge' });

        const count = importContracts(req.sessionUserId, data);
        res.json({ success: true, imported: count });
    } catch (error) {
        console.error('JSON-Import:', error.message);
        res.status(500).json({ error: 'Import fehlgeschlagen' });
    }
});

// ============================================================================
// GLOBAL ERROR HANDLER
// ============================================================================

app.use((err, _req, res, _next) => {
    console.error('Unbehandelter Fehler:', err.message);
    res.status(500).json({ error: 'Interner Serverfehler' });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Vertragsmanagement läuft auf http://0.0.0.0:${PORT}`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM empfangen – Server wird beendet');
    db.close();
    process.exit(0);
});
