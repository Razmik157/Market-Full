require('dotenv').config();
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();

// --- ՈՒՂՂՈՒՄ. Render-ի ֆայլային համակարգի կարգավորում ---
const isRender = process.env.RENDER === 'true';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
// Ստեղծում ենք թղթապանակը, եթե չկա
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

app.use(express.static(__dirname));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ limit: '2mb', extended: true }));

// === MONGODB CONNECTION ===
const uri = process.env.MONGODB_URI;
if (!uri) {
    console.error("❌ MONGODB_URI environment variable is not set!");
    process.exit(1);
}

const client = new MongoClient(uri);
const dbName = 'marketplace';
let db;

async function connectDB() {
    try {
        await client.connect();
        db = client.db(dbName);
        console.log('✅ MongoDB connected successfully');
        return db;
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        process.exit(1);
    }
}

// Միանում ենք սերվերի գործարկման ժամանակ
connectDB();

// === DB HELPERS (MongoDB տարբերակ) ===
const getCollection = (name) => {
    if (!db) throw new Error('Database not connected');
    return db.collection(name);
};

const getProducts = async () => {
    return await getCollection('products').find({}).toArray();
};

const addProduct = async (product) => {
    return await getCollection('products').insertOne(product);
};

const deleteProduct = async (id) => {
    return await getCollection('products').deleteOne({ id: parseInt(id) });
};

const getUsers = async () => {
    return await getCollection('users').find({}).toArray();
};

const addUser = async (user) => {
    return await getCollection('users').insertOne(user);
};

const findUserByEmail = async (email) => {
    return await getCollection('users').findOne({ email: email });
};

const getOrders = async () => {
    return await getCollection('orders').find({}).toArray();
};

const addOrder = async (order) => {
    return await getCollection('orders').insertOne(order);
};

const updateOrderStatus = async (orderId, newStatus) => {
    return await getCollection('orders').updateOne(
        { id: parseInt(orderId) },
        { $set: { status: newStatus } }
    );
};

const getMessages = async () => {
    return await getCollection('messages').find({}).toArray();
};

const addMessage = async (message) => {
    return await getCollection('messages').insertOne(message);
};

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const ADMIN_PIN = process.env.ADMIN_PIN;
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

const adminBruteforceLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "Չափազանց շատ սխալ փորձեր։ Փորձեք 15 րոպե անց" },
    skipSuccessfulRequests: true,
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

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

// ─── ADMIN AUTH ────────────────────────────────────────
const adminAuth = (req, res, next) => {
    const token = req.headers['x-admin-token'];
    const pin = req.headers['x-admin-pin'];
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
        } catch (e) {}
    }
    adminAuth(req, res, next);
};

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
app.get('/products', async (req, res) => {
    try {
        const products = await getProducts();
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/products', adminJWTAuth, upload.single('image'), async (req, res) => {
    const { title, desc, cat, price } = req.body;
    if (!title || !price) return res.status(400).json({ error: "title և price պարտադիր են" });

    let imgUrl = 'https://via.placeholder.com/400';
    if (req.file) {
        imgUrl = `/uploads/${req.file.filename}`;
    }

    const newProduct = {
        id: Date.now(),
        title: title.substring(0, 200),
        desc: (desc || "").substring(0, 1000),
        cat: cat || "General",
        price: parseFloat(price),
        img: imgUrl
    };

    try {
        await addProduct(newProduct);
        res.json(newProduct);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/products/:id', adminJWTAuth, async (req, res) => {
    try {
        const products = await getProducts();
        const product = products.find(p => p.id == req.params.id);
        if (product && product.img && product.img.startsWith('/uploads/')) {
            const filePath = path.join(UPLOADS_DIR, path.basename(product.img));
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }
        await deleteProduct(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ─── CLIENT AUTH ───────────────────────────────────────
app.post('/register-client', loginLimiter, async (req, res) => {
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ success: false, message: "Անուն և email պարտադիր են" });
    const cleanEmail = email.toLowerCase().trim();

    const existingUser = await findUserByEmail(cleanEmail);
    if (existingUser) {
        return res.status(400).json({ success: false, message: "Այս էլ. փոստը արդեն գրանցված է" });
    }

    const newPin = Math.floor(1000 + Math.random() * 9000).toString();
    const user = { id: Date.now(), name: name.substring(0, 60), email: cleanEmail, pin: newPin, regDate: new Date().toLocaleString() };
    await addUser(user);
    res.json({ success: true, pin: newPin });
});

app.post('/login-client', loginLimiter, async (req, res) => {
    const { email, pin } = req.body;
    if (!email || !pin) return res.status(400).json({ success: false, message: "email և pin պարտադիր են" });
    const user = await findUserByEmail(email.toLowerCase().trim());
    if (user && user.pin === pin) {
        res.json({ success: true, name: user.name });
    } else {
        res.status(401).json({ success: false, message: "Սխալ էլ. փոստ կամ PIN" });
    }
});

app.post('/login-client-jwt', loginLimiter, async (req, res) => {
    const { email, pin } = req.body;
    if (!email || !pin) return res.status(400).json({ success: false, message: "email և pin պարտադիր են" });
    const user = await findUserByEmail(email.toLowerCase().trim());
    if (user && user.pin === pin) {
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

app.get('/my-orders/:email', async (req, res) => {
    const email = req.params.email.toLowerCase().trim();
    const pin = req.query.pin;
    if (!pin) return res.status(400).json({ error: "PIN պարտադիր է" });
    const user = await findUserByEmail(email);
    if (!user || user.pin !== pin) return res.status(401).json({ error: "Access Denied" });
    const allOrders = await getOrders();
    const userOrders = allOrders.filter(o => o.email.toLowerCase().trim() === email);
    res.json(userOrders);
});

app.post('/orders', strictRateLimiter, async (req, res) => {
    const { customer, email, pin, items, total } = req.body;
    if (!email || !pin) return res.status(400).json({ error: "email և pin պարտադիր են" });

    const user = await findUserByEmail(email.toLowerCase().trim());
    if (!user || user.pin !== pin) return res.status(401).json({ error: "Սխալ email կամ PIN" });

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
    await addOrder(newOrder);
    res.json({ success: true });
});

// ─── MESSAGES ──────────────────────────────────────────
app.post('/messages', chatLimiter, upload.single('attachment'), async (req, res) => {
    const email = req.body.email ? req.body.email.toLowerCase().trim() : null;
    const pin = req.body.pin || null;

    if (!email || !pin) return res.status(400).json({ error: "email և pin պարտադիր են" });

    const user = await findUserByEmail(email);
    if (!user || user.pin !== pin) return res.status(401).json({ error: "Սխալ PIN" });

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
    await addMessage(newMessage);
    res.json({ success: true });
});

app.get('/my-messages/:email', async (req, res) => {
    const clientEmail = req.params.email.toLowerCase().trim();
    const clientPin = req.query.pin;
    if (!clientPin) return res.status(400).json({ error: "PIN պարտադիր է" });

    const user = await findUserByEmail(clientEmail);
    if (!user || user.pin !== clientPin) return res.status(401).json({ error: "Սխալ PIN" });

    const allMessages = await getMessages();
    const userMsgs = allMessages.filter(m => m.email === clientEmail && m.pin === clientPin);
    res.json(userMsgs);
});

// ─── ADMIN ENDPOINTS ───────────────────────────────────
app.get('/admin/orders', adminJWTAuth, async (req, res) => {
    const orders = await getOrders();
    res.json(orders);
});

app.post('/admin/update-order-status', adminJWTAuth, async (req, res) => {
    const { orderId, newStatus } = req.body;
    const VALID_STATUSES = ['Ընդունված', 'Պատրաստվում է', 'Ավարտված'];
    if (!VALID_STATUSES.includes(newStatus)) return res.status(400).json({ error: "Անվավեր status" });

    const allOrders = await getOrders();
    const order = allOrders.find(o => o.id == orderId);
    if (!order) return res.status(404).json({ error: "Order not found" });

    await updateOrderStatus(orderId, newStatus);
    res.json({ success: true });
});

app.get('/admin/messages', adminJWTAuth, async (req, res) => {
    const allMessages = await getMessages();
    const grouped = {};
    allMessages.forEach(m => {
        if (!grouped[m.email]) {
            grouped[m.email] = { email: m.email, name: m.name, messages: [] };
        }
        grouped[m.email].messages.push(m);
    });
    res.json(Object.values(grouped));
});

app.get('/admin/users', adminJWTAuth, async (req, res) => {
    const users = await getUsers();
    res.json(users.map(({ pin, ...u }) => u));
});

app.post('/admin/send-message', adminJWTAuth, chatLimiter, upload.single('attachment'), async (req, res) => {
    const email = req.body.email ? req.body.email.toLowerCase().trim() : null;
    const message = req.body.message || req.body.text || "";

    if (!email) return res.status(400).json({ error: "email պարտադիր է" });

    const user = await findUserByEmail(email);
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
    await addMessage(newMsg);
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
    res.sendFile(path.join(__dirname, 'Market.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log("-----------------------------------------");
    console.log("🚀 Techno Lab Server is running!");
    console.log(`🌐 http://localhost:${PORT}`);
    console.log("-----------------------------------------");
});
