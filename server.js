require('dotenv').config();
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();

// --- ՈՒՂՂՈՒՄ 1: UPLOADS_DIR սահմանված է ավելի վաղ ---
const isRender = process.env.RENDER === 'true'; 
const UPLOADS_DIR = isRender ? '/var/data/uploads' : path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ limit: '2mb', extended: true }));

// --- ՈՒՂՂՈՒՄ 2: Static ֆայլերի ճիշտ հերթականություն ---
app.use(express.static('public')); 
app.use('/uploads', express.static(UPLOADS_DIR));

const DB_FILE = process.env.DB_FILE || 'db.json';

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const ADMIN_PIN   = process.env.ADMIN_PIN;
if (!ADMIN_TOKEN || !ADMIN_PIN) {
    console.error("❌ ADMIN_TOKEN կամ ADMIN_PIN .env-ում չկա։ Կանգնեցնում եմ.");
    process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || 'temp-jwt-secret-change-in-production-' + Date.now();

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ['.stl', '.obj', '.glb', '.gltf', '.3mf', '.jpg', '.jpeg', '.png', '.pdf', '.zip'];

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const safeName = Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, safeName);
    }
});

const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_EXTENSIONS.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('Ֆայլի տեսակը չի թույլատրվում'), false);
    }
};

const upload = multer({ storage, limits: { fileSize: MAX_FILE_SIZE }, fileFilter });
const uploadFields = upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'attachment', maxCount: 1 }
]);

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: "Չափազանց շատ փորձեր" } });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 25 });
const strictRateLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });
const adminBruteforceLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "Չափազանց շատ սխալ փորձեր" },
    skipSuccessfulRequests: true
});

const failedAttempts = new Map();

function checkAndBlockIP(ip) {
    const now = Date.now();
    const record = failedAttempts.get(ip);
    if (record && record.blockUntil && now < record.blockUntil) {
        return { blocked: true, remainingMinutes: Math.ceil((record.blockUntil - now) / 60000) };
    }
    return { blocked: false };
}

function recordFailedAttempt(ip) {
    const now = Date.now();
    let record = failedAttempts.get(ip) || { count: 0, blockUntil: null };
    record.count++;
    if (record.count >= 5) record.blockUntil = now + (15 * 60 * 1000);
    failedAttempts.set(ip, record);
    return record;
}

function clearFailedAttempts(ip) { failedAttempts.delete(ip); }

const readDB = () => {
    if (!fs.existsSync(DB_FILE)) {
        const init = { products: [], orders: [], users: [], messages: [] };
        fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
        return init;
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
};

const writeDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

const adminAuth = (req, res, next) => {
    const token = req.headers['x-admin-token'];
    const pin   = req.headers['x-admin-pin'];
    if (token === ADMIN_TOKEN && pin === ADMIN_PIN) next();
    else res.status(403).json({ error: "Access Denied" });
};

const adminJWTAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
            const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
            if (decoded.role === 'admin') return next();
        } catch(e) {}
    }
    adminAuth(req, res, next);
};

app.post('/admin/login', adminBruteforceLimiter, (req, res) => {
    const clientIp = req.ip;
    const { blocked, remainingMinutes } = checkAndBlockIP(clientIp);
    if (blocked) return res.status(429).json({ error: `Արգելափակված եք ${remainingMinutes} րոպեով` });
    
    if (req.body.pin === ADMIN_PIN) {
        clearFailedAttempts(clientIp);
        res.json({ success: true, token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '2h' }) });
    } else {
        recordFailedAttempt(clientIp);
        res.status(401).json({ error: "Invalid admin PIN" });
    }
});

app.get('/products', (req, res) => res.json(readDB().products || []));

app.post('/products', adminJWTAuth, upload.single('image'), (req, res) => {
    const { title, price } = req.body;
    if (!title || !price) return res.status(400).json({ error: "title և price պարտադիր են" });
    const db = readDB();
    const newProduct = { id: Date.now(), title, price, img: req.file ? `/uploads/${req.file.filename}` : 'https://via.placeholder.com/400' };
    db.products.push(newProduct);
    writeDB(db);
    res.json(newProduct);
});

app.delete('/products/:id', adminJWTAuth, (req, res) => {
    const db = readDB();
    db.products = db.products.filter(p => p.id != req.params.id);
    writeDB(db);
    res.json({ success: true });
});

app.post('/register-client', loginLimiter, (req, res) => {
    const { name, email } = req.body;
    const db = readDB();
    const newPin = Math.floor(1000 + Math.random() * 9000).toString();
    db.users.push({ id: Date.now(), name, email: email.toLowerCase().trim(), pin: newPin });
    writeDB(db);
    res.json({ success: true, pin: newPin });
});

// ... (մնացած endpoint-ները թողնում ենք նույնը)

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: "Server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Techno Lab Server is running on port ${PORT}`));
