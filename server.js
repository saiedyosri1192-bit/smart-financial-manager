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

// ذاكرة تخزين مؤقتة للأنظمة التي لا تمتلك قاعدة بيانات سحابية مفعلة
let inMemoryUsers = [];
let inMemoryTransactions = [];

let isPg = false;
let pool = null;

if (process.env.DATABASE_URL) {
    try {
        const { Pool } = require('pg');
        pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false }
        });
        isPg = true;
        
        pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                type VARCHAR(20) NOT NULL,
                description TEXT NOT NULL,
                amount NUMERIC(12, 2) NOT NULL,
                category VARCHAR(100) NOT NULL,
                date DATE NOT NULL
            );
        `).then(() => console.log('PostgreSQL Connected')).catch(err => console.error('PG Init Error:', err));
    } catch (e) {
        console.log('Running in Memory mode');
    }
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
        if (isPg) {
            await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
        } else {
            if (inMemoryUsers.find(u => u.username === username)) {
                return res.status(400).json({ message: 'اسم المستخدم مسجل مسبقاً' });
            }
            inMemoryUsers.push({ id: Date.now(), username, password: hashedPassword });
        }
        res.json({ message: 'تم إنشاء الحساب بنجاح' });
    } catch (err) {
        res.status(400).json({ message: 'اسم المستخدم مسجل مسبقاً أو حدث خطأ' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user;
        if (isPg) {
            const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            user = result.rows[0];
        } else {
            user = inMemoryUsers.find(u => u.username === username);
        }

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
        if (isPg) {
            const result = await pool.query(
                "SELECT id, type, description, amount::float, category, TO_CHAR(date, 'YYYY-MM-DD') as date FROM transactions WHERE user_id = $1 ORDER BY date DESC",
                [req.user.id]
            );
            res.json(result.rows);
        } else {
            const userTx = inMemoryTransactions.filter(t => t.user_id === req.user.id);
            res.json(userTx);
        }
    } catch (err) {
        res.status(500).json({ message: 'خطأ في جلب البيانات' });
    }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
    const { type, description, amount, category, date } = req.body;
    try {
        let newId = Date.now();
        if (isPg) {
            const result = await pool.query(
                'INSERT INTO transactions (user_id, type, description, amount, category, date) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [req.user.id, type, description, amount, category, date]
            );
            newId = result.rows[0].id;
        } else {
            inMemoryTransactions.unshift({ id: newId, user_id: req.user.id, type, description, amount: parseFloat(amount), category, date });
        }
        res.json({ id: newId, type, description, amount, category, date });
    } catch (err) {
        res.status(500).json({ message: 'خطأ في حفظ العملية' });
    }
});

app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        if (isPg) {
            await pool.query('DELETE FROM transactions WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
        } else {
            inMemoryTransactions = inMemoryTransactions.filter(t => !(t.id == req.params.id && t.user_id === req.user.id));
        }
        res.json({ message: 'تم الحذف بنجاح' });
    } catch (err) {
        res.status(500).json({ message: 'خطأ في الحذف' });
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
