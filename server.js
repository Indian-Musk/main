const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');
const SQLiteStore = require('connect-sqlite3')(session);
const app = express();
// const port = 3000;
// To this
const port = process.env.PORT || 3000;
// Security and Encoding
const escapeHTML = str => String(str).replace(/[&<>'"]/g, tag => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
}[tag]));

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', concurrentDB: true }),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Security Headers
app.use((req, res, next) => {
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    next();
});

// Database Setup
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
        process.exit(1);
    }
    console.log('✅ Connected to SQLite database');
    db.run('PRAGMA foreign_keys = ON;');
});

// Database Initialization
const initializeDatabase = () => {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            isAdmin BOOLEAN DEFAULT 0,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) console.error('❌ Users table error:', err.message);
            else console.log('✔️ Users table ready');
        });

        db.run(`CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
        )`, (err) => {
            if (err) console.error('❌ Contacts table error:', err.message);
            else console.log('✔️ Contacts table ready');
        });
    });
};

// Admin Initialization
const initializeAdmin = () => {
    return new Promise((resolve, reject) => {
        db.get("SELECT * FROM users WHERE isAdmin = 1", async (err, row) => {
            if (err) return reject(err);
            
            if (!row) {
                const adminUsername = process.env.ADMIN_USERNAME || 'admin';
                const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
                
                try {
                    const hashedPassword = await bcrypt.hash(adminPassword, 10);
                    db.run(
                        'INSERT INTO users (username, password, isAdmin) VALUES (?, ?, 1)',
                        [adminUsername, hashedPassword],
                        (err) => {
                            if (err) return reject(err);
                            console.log(`👑 Admin user created: ${adminUsername}`);
                            resolve();
                        }
                    );
                } catch (error) {
                    reject(error);
                }
            } else {
                console.log('👑 Admin user already exists');
                resolve();
            }
        });
    });
};

// Middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) return res.status(401).send('Unauthorized');
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.isAdmin) return res.status(403).send('Forbidden');
    next();
};

// Routes
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword],
            function(err) {
                if (err) return res.status(400).json({ error: 'Username exists' });
                res.sendStatus(201);
            }
        );
    } catch (error) {
        res.status(500).send('Server error');
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).send('Database error');
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send('Invalid credentials');
        }
        
        req.session.userId = user.id;
        req.session.isAdmin = user.isAdmin;
        res.sendStatus(200);
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Logout failed');
        res.sendStatus(200);
    });
});

app.get('/api/user', (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });
    
    db.get('SELECT id, username, isAdmin FROM users WHERE id = ?', 
    [req.session.userId], 
    (err, user) => {
        if (err || !user) return res.json({ loggedIn: false });
        res.json({ loggedIn: true, user });
    });
});

app.post('/contact', requireAuth, (req, res) => {
    const { name, email, message } = req.body;
    
    if (!name || !email || !message) {
        return res.status(400).send('All fields are required');
    }

    db.run(
        'INSERT INTO contacts (userId, name, email, message) VALUES (?, ?, ?, ?)',
        [req.session.userId, name, email, message],
        function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Error saving message');
            }
            res.redirect('/#contact');
        }
    );
});

// Admin Dashboard
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
    db.serialize(() => {
        db.all(`SELECT 
                    users.username as user_name,
                    contacts.name as contact_name,
                    contacts.email,
                    contacts.message,
                    contacts.created_at as message_date
                FROM contacts
                LEFT JOIN users ON contacts.userId = users.id
                ORDER BY contacts.created_at DESC`, 
        (err, messages) => {
            if (err) {
                console.error('Messages error:', err);
                return res.status(500).send('Error loading messages');
            }

            db.all(`SELECT 
                        id,
                        username,
                        isAdmin,
                        createdAt as registration_date
                    FROM users
                    ORDER BY createdAt DESC`, 
            (err, users) => {
                if (err) {
                    console.error('Users error:', err);
                    return res.status(500).send('Error loading users');
                }

                const adminHTML = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Admin Dashboard</title>
                    <style>
                        body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #fff; padding: 2rem; }
                        .admin-container { max-width: 1200px; margin: 0 auto; }
                        h1 { color: #00ff88; margin-bottom: 2rem; }
                        .data-section { margin-bottom: 3rem; background: rgba(255,255,255,0.1); padding: 2rem; border-radius: 15px; }
                        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
                        th, td { padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
                        th { background-color: #0f3460; }
                        .back-link { display: inline-block; margin-bottom: 2rem; color: #00ff88; text-decoration: none; }
                    </style>
                </head>
                <body>
                    <div class="admin-container">
                        <a href="/" class="back-link">← Back to Main Site</a>
                        <h1>Admin Dashboard</h1>
                        
                        <div class="data-section">
                            <h2>Registered Users (${users.length})</h2>
                            <table>
                                <tr><th>ID</th><th>Username</th><th>Role</th><th>Registered</th></tr>
                                ${users.map(user => `
                                    <tr>
                                        <td>${user.id}</td>
                                        <td>${escapeHTML(user.username)}</td>
                                        <td>${user.isAdmin ? 'Admin ✅' : 'User'}</td>
                                        <td>${new Date(user.registration_date).toLocaleString()}</td>
                                    </tr>
                                `).join('')}
                            </table>
                        </div>

                        <div class="data-section">
                            <h2>Contact Submissions (${messages.length})</h2>
                            <table>
                                <tr><th>User</th><th>Name</th><th>Email</th><th>Message</th><th>Date</th></tr>
                                ${messages.map(message => `
                                    <tr>
                                        <td>${escapeHTML(message.user_name || 'Guest')}</td>
                                        <td>${escapeHTML(message.contact_name)}</td>
                                        <td>${escapeHTML(message.email)}</td>
                                        <td>${escapeHTML(message.message)}</td>
                                        <td>${new Date(message.message_date).toLocaleString()}</td>
                                    </tr>
                                `).join('')}
                            </table>
                        </div>
                    </div>
                </body>
                </html>
                `;

                res.send(adminHTML);
            });
        });
    });
});

// Server Startup
initializeDatabase();
initializeAdmin()
    .then(() => {
        app.listen(port, () => {
            console.log(`🚀 Server running at http://localhost:${port}`);
            console.log(`🔑 Default admin credentials: admin/admin123`);
        });
    })
    .catch(err => {
        console.error('🔥 Startup failed:', err);
        process.exit(1);
    });