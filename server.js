const express = require('express'); 
const bodyParser = require('body-parser');
const session = require('express-session');
const { Pool } = require('pg'); // PostgreSQL connection
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3000;

// Setup middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(session({
    secret: 'your-secret-key', 
    resave: false, 
    saveUninitialized: false, 
    cookie: { httpOnly: true, secure: false }
}));

// Initialize PostgreSQL database using provided Railway database URL
const pool = new Pool({
    connectionString: 'postgresql://postgres:tHUPclbFqTJTQrTFbUUlmwEbJhCQGeMN@postgres.railway.internal:5432/railway',
    ssl: { rejectUnauthorized: false }
});

pool.connect()
    .then(() => console.log('Connected to PostgreSQL database.'))
    .catch(err => console.error('Database connection error:', err.message));

// Function to check if a string is valid Hex
function isHex(str) {
    return /^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0;
}

// Function to decode Hex to ASCII
function hexToAscii(hex) {
    try {
        return isHex(hex) ? Buffer.from(hex, 'hex').toString('utf-8') : hex;
    } catch (error) {
        console.error("Error decoding hex:", error.message);
        return hex;
    }
}

// Authentication Middleware
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/');
    }
    next();
}

// Serve login page
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Serve only necessary static files (excluding dashboard.html)
app.use(express.static(__dirname + '/public'));

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const row = result.rows[0];

        if (!row) {
            return res.send('User not found');
        }

        // Decode only if the stored password is Hex, otherwise use as-is
        const decodedPassword = hexToAscii(row.password);

        // Compare stored password (decoded) with entered password
        if (decodedPassword === password) {
            req.session.user = { username: row.username };
            return res.redirect('/challenge'); // Redirect to challenge instead of dashboard
        } else {
            // Provide hint only if the password is stored in Hex
            if (isHex(row.password)) {
                res.setHeader("X-Debug-Hint", `Try decoding this: ${row.password}`);
            }
            return res.send('Invalid credentials');
        }
    } catch (err) {
        console.error('Database error:', err.message);
        return res.status(500).send('Database error');
    }
});

// Challenge page (Protected)
app.get('/challenge', requireLogin, (req, res) => {
    res.sendFile(__dirname + '/private/traversal.html');
});

// Directory Traversal Challenge routes
const handleFileRequest = (req, res) => {
    const file = req.query.file || '';

    // Define accessible directories
    const baseDir = path.join(__dirname, 'private');
    const hiddenDir = path.join(__dirname, 'hidden'); // Hint and Video files are stored here

    let filePath = path.join(baseDir, file);

    // Allow traversal for both hint.txt and petta.mp4
    if (file === '../petta.mp4') {
        filePath = path.join(hiddenDir, 'petta.mp4');

        // Stream the video instead of downloading
        const stat = fs.statSync(filePath);
        res.writeHead(200, {
            'Content-Type': 'video/mp4',
            'Content-Length': stat.size
        });
        fs.createReadStream(filePath).pipe(res);
        return;
    } else if (file === '../hint.txt') {
        filePath = path.join(hiddenDir, 'hint.txt');
    }

    // Block access to system files
    if (file.includes('/etc/') || file.includes('passwd') || file.includes('shadow')) {
        return res.send("Access Denied: System files cannot be accessed!");
    }

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.send("Error: File not found.");
        }
        res.send(`<pre>${data}</pre>`);
    });
};

// Handle both readfile and index.php routes
app.get('/readfile', requireLogin, handleFileRequest);
app.get('/index.php', requireLogin, handleFileRequest);

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Start the server
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running at http://0.0.0.0:${port}`);
});
