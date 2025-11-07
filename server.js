const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const compression = require('compression');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const uploadDir = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',') 
    : ['http://localhost:3000'];

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            frameSrc: ["'self'", "data:"],
            frameAncestors: ["'self'"].concat(allowedOrigins)
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many upload attempts, please try again later.'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many authentication attempts, please try again later.'
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDir = path.join(uploadDir, req.user?.id || 'anonymous');
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        cb(null, userDir);
    },
    filename: function (req, file, cb) {
        const uniqueId = uuidv4();
        const ext = path.extname(file.originalname);
        cb(null, `${uniqueId}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: (process.env.MAX_FILE_SIZE || 100) * 1024 * 1024,
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /zip|html|htm/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype) || 
                        file.mimetype === 'application/zip' ||
                        file.mimetype === 'application/x-zip-compressed' ||
                        file.mimetype === 'text/html';
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only HTML and ZIP files are allowed!'));
        }
    }
});

let uploadedFiles = [];

// Load existing files from uploads directory on startup
function loadExistingFiles() {
    const uploadsDir = path.join(__dirname, 'uploads', 'admin');
    if (fs.existsSync(uploadsDir)) {
        const files = fs.readdirSync(uploadsDir);
        files.forEach(filename => {
            const filePath = path.join(uploadsDir, filename);
            const stats = fs.statSync(filePath);
            // Use the filename without extension as the ID to match embed URLs
            const fileId = path.basename(filename, path.extname(filename));
            
            uploadedFiles.push({
                id: fileId,
                originalName: filename,
                filename: filename,
                mimetype: filename.endsWith('.html') ? 'text/html' : 'application/zip',
                type: filename.endsWith('.html') ? 'HTML' : 'ZIP',
                size: stats.size,
                uploadDate: stats.mtime,
                userId: 'admin', // Default to admin for existing files
                path: filePath
            });
        });
        console.log(`Loaded ${uploadedFiles.length} existing files from uploads directory`);
    }
}

// Load existing files on startup
loadExistingFiles();

const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

app.use(express.static('public'));
app.use('/admin', express.static('admin'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

app.get('/debug', (req, res) => {
    res.sendFile(path.join(__dirname, 'debug-preview.html'));
});

app.post('/api/auth/login', authLimiter, [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        const adminUsername = process.env.ADMIN_USERNAME || 'admin';
        const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

        if (username !== adminUsername) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, await bcrypt.hash(adminPassword, 10));
        if (!isValidPassword && password !== adminPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: 'admin', username: adminUsername },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '24h' }
        );

        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.json({ success: true, message: 'Login successful' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.json({ success: true, message: 'Logout successful' });
});

app.post('/api/upload', uploadLimiter, authenticateToken, upload.single('htmlFile'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Use the filename without extension as the ID for consistency with loadExistingFiles
        const fileId = path.basename(req.file.filename, path.extname(req.file.filename));

        const fileInfo = {
            id: fileId,
            filename: req.file.filename,
            originalName: req.file.originalname,
            size: req.file.size,
            uploadDate: new Date(),
            userId: req.user.id,
            path: req.file.path
        };

        uploadedFiles.push(fileInfo);

        res.json({
            success: true,
            message: 'File uploaded successfully',
            fileId: fileInfo.id,
            embedUrl: `/embed/${fileInfo.id}`
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.get('/api/files', authenticateToken, (req, res) => {
    const userFiles = uploadedFiles.filter(file => file.userId === req.user.id);
    res.json(userFiles);
});

app.delete('/api/files/:id', authenticateToken, (req, res) => {
    try {
        const fileId = req.params.id;
        console.log(`Delete request for file ID: ${fileId}`);
        console.log('Available files:', uploadedFiles.map(f => ({ id: f.id, userId: f.userId })));
        
        const fileIndex = uploadedFiles.findIndex(file => 
            file.id === fileId && file.userId === req.user.id
        );

        if (fileIndex === -1) {
            console.log(`File not found: ${fileId} for user: ${req.user.id}`);
            return res.status(404).json({ error: 'File not found' });
        }

        const file = uploadedFiles[fileIndex];
        console.log(`Deleting file: ${file.path}`);
        
        if (fs.existsSync(file.path)) {
            fs.unlinkSync(file.path);
            console.log(`File deleted from disk: ${file.path}`);
        } else {
            console.log(`File not found on disk: ${file.path}`);
        }

        uploadedFiles.splice(fileIndex, 1);
        console.log(`File removed from memory. Remaining files: ${uploadedFiles.length}`);
        
        res.json({ success: true, message: 'File deleted successfully' });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Delete failed' });
    }
});

app.get('/embed/:id', (req, res) => {
    try {
        const fileId = req.params.id;
        const file = uploadedFiles.find(f => f.id === fileId);

        console.log(`Embed request for file ${fileId}, preview: ${req.query.preview}, referer: ${req.headers.referer}`);
        console.log('Available files:', uploadedFiles.map(f => f.id));

        if (!file) {
            console.log(`File ${fileId} not found in uploaded files`);
            return res.status(404).send('File not found');
        }

        if (!fs.existsSync(file.path)) {
            console.log(`File ${fileId} not found on disk at path: ${file.path}`);
            return res.status(404).send('File not found on disk');
        }

        // Check if this is a preview request (from admin panel)
        const isPreview = req.query.preview === 'true' || req.headers.referer?.includes('/admin');
        
        console.log(`Serving file ${fileId}, preview mode: ${isPreview}`);
        
        // Remove X-Frame-Options for preview to allow embedding
        if (isPreview) {
            res.removeHeader('X-Frame-Options');
            res.setHeader('Content-Security-Policy', "frame-ancestors 'self' http://localhost:3000");
        } else {
            res.setHeader('X-Frame-Options', 'SAMEORIGIN');
            res.setHeader('Content-Security-Policy', "frame-ancestors 'self' " + allowedOrigins.join(' '));
        }
        
        // Add CORS headers for preview
        if (isPreview) {
            res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        
        if (path.extname(file.path).toLowerCase() === '.html' || path.extname(file.path).toLowerCase() === '.htm') {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.sendFile(path.resolve(file.path));
        } else {
            res.download(file.path, file.originalName);
        }
    } catch (error) {
        console.error('Embed error:', error);
        res.status(500).send('Internal server error');
    }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large' });
        }
    }
    res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Admin panel: http://localhost:${PORT}/admin`);
    console.log(`🌐 Public site: http://localhost:${PORT}`);
});