const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'smart_financial_manager_secret_key_2026';

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

let dbQuery;
const isPg = !!process.env.DATABASE_URL;

if (isPg) {
    const { Pool } = require('pg');
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    dbQuery = async (text, params) => {
        const res = await pool.query(text, params);
        return res;
    };

    const initPg = async () => {
        try {
            await dbQuery(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                );
            `);
            await dbQuery(`
                CREATE TABLE IF NOT EXISTS transactions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    type VARCHAR(20) NOT NULL,
                    description TEXT NOT NULL,
                    amount NUMERIC(12, 2) NOT NULL,
                    category VARCHAR(100) NOT NULL,
                    date DATE NOT NULL
                );
            `);
            console.log('PostgreSQL database initialized successfully.');
        } catch (err) {
            console.error('PostgreSQL initialization error:', err);
        }
    };
    initPg();
} else {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./financial_db.sqlite', (err) => {
        if (err) console.error('SQLite connection error:', err);
        else console.log('SQLite database connected locally.');
    });

    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT,
            description TEXT,
            amount REAL,
            category TEXT,
            date TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
    });

    dbQuery = (text, params = []) => {
        return new Promise((resolve, reject) => {
            if (text.trim().toUpperCase().startsWith('SELECT')) {
                db.all(text.replace(/\$\d+/g, '?'), params, (err, rows) => {
                    if (err) reject(err);
                    else resolve({ rows });
                });
            } else if (text.trim().toUpperCase().startsWith('INSERT')) {
                db.run(text.replace(/\$\d+/g, '?'), params, function (err) {
                    if (err) reject(err);
                    else resolve({ rows: [{ id: this.lastID }] });
                });
            } else {
                db.run(text.replace(/\$\d+/g, '?'), params, function (err) {
                    if (err) reject(err);
                    else resolve({ rows: [] });
                });
            }
        });
    };
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'يرجى تسجيل الدخول أولاً' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'جلسة غير صالحة' });
        req.user = user;
        next();
    });
}

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'يرجى ملء كافة الحقول' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await dbQuery('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
        res.json({ message: 'تم إنشاء الحساب بنجاح' });
    } catch (err) {
        if (err.message && (err.message.includes('UNIQUE') || err.code === '23505')) {
            return res.status(400).json({ message: 'اسم المستخدم مسجل مسبقاً' });
        }
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await dbQuery('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) return res.status(400).json({ message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: user.username });
    } catch (err) {
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const query = isPg 
            ? 'SELECT id, type, description, amount::float, category, TO_CHAR(date, 'YYYY-MM-DD') as date FROM transactions WHERE user_id = $1 ORDER BY date DESC'
            : 'SELECT id, type, description, amount, category, date FROM transactions WHERE user_id = $1 ORDER BY date DESC';
        const result = await dbQuery(query, [req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'خطأ في جلب البيانات' });
    }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
    const { type, description, amount, category, date } = req.body;
    try {
        const result = await dbQuery(
            'INSERT INTO transactions (user_id, type, description, amount, category, date) VALUES ($1, $2, $3, $4, $5, $6)',
            [req.user.id, type, description, amount, category, date]
        );
        const newId = result.rows[0] ? result.rows[0].id : Date.now();
        res.json({ id: newId, type, description, amount, category, date });
    } catch (err) {
        res.status(500).json({ message: 'خطأ في حفظ العملية' });
    }
});

app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        await dbQuery('DELETE FROM transactions WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
        res.json({ message: 'تم الحذف بنجاح' });
    } catch (err) {
        res.status(500).json({ message: 'خطأ في الحذف' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
