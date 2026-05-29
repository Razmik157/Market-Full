require('dotenv').config({ path: 'pass.env.local' });
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();

//app.use(helmet({
//crossOriginResourcePolicy: { policy: "cross-origin" }
//}));
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ limit: '2mb', extended: true }));
app.use('/uploads', express.static('uploads'));

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
        if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
        cb(null, 'uploads/');
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

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Չափազանց շատ փորձեր։ Փորձեք մի քանի րոպե անց" }
});

const chatLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 25
});

const strictRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: "Too many requests. Please slow down." }
});

// ✅ ADMIN BRUTEFORCE PROTECTION
const adminBruteforceLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "Չափազանց շատ սխալ փորձեր։ Փորձեք 15 րոպե անց" },
    skipSuccessfulRequests: true,
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

// ✅ Failed attempts tracking
const failedAttempts = new Map();

function checkAndBlockIP(ip) {
    const now = Date.now();
    const record = failedAttempts.get(ip);
    if (record && record.blockUntil && now < record.blockUntil) {
        const remainingMinutes = Math.ceil((record.blockUntil - now) / 60000);
        return { blocked: true, remainingMinutes };
    }
    if (record && record.blockUntil && now >= record.blockUntil) {
        failedAttempts.delete(ip);
    }
    return { blocked: false };
}

function recordFailedAttempt(ip) {
    const now = Date.now();
    let record = failedAttempts.get(ip);
    if (!record) {
        record = { count: 1, lastAttempt: now, blockUntil: null };
    } else {
        record.count++;
        record.lastAttempt = now;
        if (record.count >= 5 && !record.blockUntil) {
            record.blockUntil = now + (15 * 60 * 1000);
        } else if (record.count >= 10 && record.blockUntil === now + (15 * 60 * 1000)) {
            record.blockUntil = now + (60 * 60 * 1000);
        } else if (record.count >= 20) {
            record.blockUntil = now + (24 * 60 * 60 * 1000);
        }
    }
    failedAttempts.set(ip, record);
    return record;
}

function clearFailedAttempts(ip) {
    failedAttempts.delete(ip);
}

// ─── DB ────────────────────────────────────────────────
const readDB = () => {
    if (!fs.existsSync(DB_FILE)) {
        const init = { products: [], orders: [], users: [], messages: [] };
        fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
        return init;
    }
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!data.users)    data.users    = [];
    if (!data.orders)   data.orders   = [];
    if (!data.messages) data.messages = [];
    return data;
};

const writeDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

// ─── ADMIN AUTH ────────────────────────────────────────
const adminAuth = (req, res, next) => {
    const token = req.headers['x-admin-token'];
    const pin   = req.headers['x-admin-pin'];
    if (token === ADMIN_TOKEN && pin === ADMIN_PIN) {
        next();
    } else {
        res.status(403).json({ error: "Access Denied" });
    }
};

const adminJWTAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role === 'admin') {
                return next();
            }
        } catch(e) {}
    }
    adminAuth(req, res, next);
};

// ✅ UPDATED: Admin login with bruteforce protection
app.post('/admin/login', adminBruteforceLimiter, (req, res) => {
    const clientIp = req.ip || req.connection.remoteAddress;
    
    const { blocked, remainingMinutes } = checkAndBlockIP(clientIp);
    if (blocked) {
        return res.status(429).json({ 
            error: `Արգելափակված եք ${remainingMinutes} րոպեով`,
            blockedUntil: remainingMinutes
        });
    }
    
    const { pin } = req.body;
    if (!pin) {
        recordFailedAttempt(clientIp);
        return res.status(400).json({ error: "PIN պարտադիր է" });
    }
    
    if (pin === ADMIN_PIN) {
        clearFailedAttempts(clientIp);
        const adminToken = jwt.sign(
            { role: 'admin', timestamp: Date.now(), ip: clientIp },
            JWT_SECRET,
            { expiresIn: '2h' }
        );
        res.json({ success: true, token: adminToken });
    } else {
        const record = recordFailedAttempt(clientIp);
        const remainingAttempts = Math.max(0, 5 - record.count);
        res.status(401).json({ 
            error: "Invalid admin PIN",
            remainingAttempts: remainingAttempts,
            message: remainingAttempts > 0 
                ? `Մնացել է ${remainingAttempts} փորձ` 
                : "Պիտի սպասեք 15 րոպե"
        });
    }
});

// ─── PRODUCTS ──────────────────────────────────────────
app.get('/products', (req, res) => {
    const db = readDB();
    res.json(db.products);
});

app.post('/products', adminJWTAuth, upload.single('image'), (req, res) => {
    const { title, desc, cat, price } = req.body;
    if (!title || !price) return res.status(400).json({ error: "title և price պարտադիր են" });

    let imgUrl = 'https://via.placeholder.com/400';
    if (req.file) {
        imgUrl = `/uploads/${req.file.filename}`;
    }

    const db = readDB();
    const newProduct = {
        id: Date.now(),
        title: title.substring(0, 200),
        desc: (desc || "").substring(0, 1000),
        cat: cat || "General",
        price: parseFloat(price),
        img: imgUrl
    };
    db.products.push(newProduct);
    writeDB(db);
    res.json(newProduct);
});

app.delete('/products/:id', adminJWTAuth, (req, res) => {
    const db = readDB();
    const product = db.products.find(p => p.id == req.params.id);
    if (product && product.img && product.img.startsWith('/uploads/')) {
        const filePath = path.join(__dirname, product.img);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    db.products = db.products.filter(p => p.id != req.params.id);
    writeDB(db);
    res.json({ success: true });
});

// ─── CLIENT AUTH ───────────────────────────────────────
app.post('/register-client', loginLimiter, (req, res) => {
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ success: false, message: "Անուն և email պարտադիր են" });
    const cleanEmail = email.toLowerCase().trim();
    const db = readDB();

    if (db.users.find(u => u.email === cleanEmail)) {
        return res.status(400).json({ success: false, message: "Այս էլ. փոստը արդեն գրանցված է" });
    }

    const newPin = Math.floor(1000 + Math.random() * 9000).toString();
    const user = { id: Date.now(), name: name.substring(0, 60), email: cleanEmail, pin: newPin, regDate: new Date().toLocaleString() };
    db.users.push(user);
    writeDB(db);
    res.json({ success: true, pin: newPin });
});

app.post('/login-client', loginLimiter, (req, res) => {
    const { email, pin } = req.body;
    if (!email || !pin) return res.status(400).json({ success: false, message: "email և pin պարտադիր են" });
    const db = readDB();
    const user = db.users.find(u => u.email === email.toLowerCase().trim() && u.pin === pin);
    if (user) {
        res.json({ success: true, name: user.name });
    } else {
        res.status(401).json({ success: false, message: "Սխալ էլ. փոստ կամ PIN" });
    }
});

app.post('/login-client-jwt', loginLimiter, (req, res) => {
    const { email, pin } = req.body;
    if (!email || !pin) return res.status(400).json({ success: false, message: "email և pin պարտադիր են" });
    const db = readDB();
    const user = db.users.find(u => u.email === email.toLowerCase().trim() && u.pin === pin);
    if (user) {
        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({ success: true, name: user.name, token });
    } else {
        res.status(401).json({ success: false, message: "Սխալ էլ. փոստ կամ PIN" });
    }
});

app.get('/my-orders/:email', (req, res) => {
    const db = readDB();
    const email = req.params.email.toLowerCase().trim();
    const pin = req.query.pin;
    if (!pin) return res.status(400).json({ error: "PIN պարտադիր է" });
    const user = db.users.find(u => u.email === email && u.pin === pin);
    if (!user) return res.status(401).json({ error: "Access Denied" });
    const userOrders = db.orders.filter(o => o.email.toLowerCase().trim() === email);
    res.json(userOrders);
});

app.post('/orders', strictRateLimiter, (req, res) => {
    const { customer, email, pin, items, total } = req.body;
    if (!email || !pin) return res.status(400).json({ error: "email և pin պարտադիր են" });

    const db = readDB();

    const user = db.users.find(u => u.email === email.toLowerCase().trim() && u.pin === pin);
    if (!user) return res.status(401).json({ error: "Սխալ email կամ PIN" });

    if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "Ապրանք չկա" });
    }

    const newOrder = {
        id: Date.now(),
        customer: (customer || user.name).substring(0, 100),
        email: email.toLowerCase().trim(),
        items,
        total: parseFloat(total) || 0,
        modelUrl: req.body.modelUrl || null,
        date: new Date().toLocaleString(),
        status: 'Ընդունված'
    };
    db.orders.push(newOrder);
    writeDB(db);
    res.json({ success: true });
});

// ─── MESSAGES ──────────────────────────────────────────
app.post('/messages', chatLimiter, upload.single('attachment'), (req, res) => {
    const db = readDB();
    const email = req.body.email ? req.body.email.toLowerCase().trim() : null;
    const pin   = req.body.pin || null;

    if (!email || !pin) return res.status(400).json({ error: "email և pin պարտադիր են" });

    const user = db.users.find(u => u.email === email && u.pin === pin);
    if (!user) return res.status(401).json({ error: "Սխալ PIN" });

    let attachment = null;
    if (req.file) {
        attachment = { name: req.file.originalname, url: `/uploads/${req.file.filename}` };
    }

    const msg = req.body.message || "";
    if (!msg.trim() && !attachment) return res.status(400).json({ error: "Հաղորդագրություն կամ ֆայլ պարտադիր է" });

    const newMessage = {
        id: Date.now(),
        name: user.name,
        email,
        pin,
        message: msg.substring(0, 2000),
        sender: 'client',
        attachment,
        date: new Date().toLocaleString()
    };
    db.messages.push(newMessage);
    writeDB(db);
    res.json({ success: true });
});

app.get('/my-messages/:email', (req, res) => {
    const db = readDB();
    const clientEmail = req.params.email.toLowerCase().trim();
    const clientPin   = req.query.pin;
    if (!clientPin) return res.status(400).json({ error: "PIN պարտադիր է" });

    const user = db.users.find(u => u.email === clientEmail && u.pin === clientPin);
    if (!user) return res.status(401).json({ error: "Սխալ PIN" });

    const userMsgs = db.messages.filter(m => m.email === clientEmail && m.pin === clientPin);
    res.json(userMsgs);
});

// ─── ADMIN ENDPOINTS ───────────────────────────────────
app.get('/admin/orders', adminJWTAuth, (req, res) => {
    res.json(readDB().orders);
});

app.post('/admin/update-order-status', adminJWTAuth, (req, res) => {
    const { orderId, newStatus } = req.body;
    const VALID_STATUSES = ['Ընդունված', 'Պատրաստվում է', 'Ավարտված'];
    if (!VALID_STATUSES.includes(newStatus)) return res.status(400).json({ error: "Անվավեր status" });

    const db = readDB();
    const idx = db.orders.findIndex(o => o.id == orderId);
    if (idx === -1) return res.status(404).json({ error: "Order not found" });

    db.orders[idx].status = newStatus;
    writeDB(db);
    res.json({ success: true });
});

app.get('/admin/messages', adminJWTAuth, (req, res) => {
    const db = readDB();
    const grouped = {};
    (db.messages || []).forEach(m => {
        if (!grouped[m.email]) {
            grouped[m.email] = { email: m.email, name: m.name, messages: [] };
        }
        grouped[m.email].messages.push(m);
    });
    res.json(Object.values(grouped));
});

app.get('/admin/users', adminJWTAuth, (req, res) => {
    const db = readDB();
    res.json(db.users.map(({ pin, ...u }) => u));
});

app.post('/admin/send-message', adminJWTAuth, chatLimiter, upload.single('attachment'), (req, res) => {
    const db = readDB();
    const email   = req.body.email ? req.body.email.toLowerCase().trim() : null;
    const message = req.body.message || req.body.text || "";

    if (!email) return res.status(400).json({ error: "email պարտադիր է" });

    const user = db.users.find(u => u.email === email);
    if (!user) return res.status(404).json({ error: "User not found" });

    let attachment = null;
    if (req.file) {
        attachment = { name: req.file.originalname, url: `/uploads/${req.file.filename}` };
    }

    if (!message.trim() && !attachment) return res.status(400).json({ error: "Հաղորդագրություն կամ ֆայլ պարտադիր է" });

    const newMsg = {
        id: Date.now(),
        name: "Techno Lab",
        email,
        pin: user.pin,
        message: message.substring(0, 2000),
        sender: 'admin',
        attachment,
        date: new Date().toLocaleString()
    };
    db.messages.push(newMsg);
    writeDB(db);
    res.json({ success: true });
});

// ─── ERROR HANDLER ─────────────────────────────────────
app.use((err, req, res, next) => {
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: "Ֆայլը շատ մեծ է (max 50MB)" });
    }
    if (err.message === 'Ֆայլի տեսակը չի թույլատրվում') {
        return res.status(415).json({ error: err.message });
    }
    console.error(err);
    res.status(500).json({ error: "Server error" });
});

// ─── START ─────────────────────────────────────────────
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'marketplace.html'));
});

app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log("-----------------------------------------");
    console.log("🚀 Techno Lab Server is running!");
    console.log(`🌐 http://localhost:${PORT}`);
    console.log("-----------------------------------------");
});

