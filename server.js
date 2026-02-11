const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// 中间件
app.use(cors());
app.use(express.json());

// MongoDB连接
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/cassell-academy';
mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).catch(err => console.log('MongoDB连接失败:', err));

// JWT密钥
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ============ 数据库模型 ============

// 用户模型
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'super_admin'], required: true },
    createdAt: { type: Date, default: Date.now },
    createdBy: { type: String },
});

const User = mongoose.model('User', userSchema);

// 帖子模型
const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: String, required: true },
    authorRole: { type: String, enum: ['admin', 'public_user'], required: true },
    likes: { type: Number, default: 0 },
    comments: [
        {
            author: String,
            content: String,
            timestamp: { type: Date, default: Date.now },
        }
    ],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

const Post = mongoose.model('Post', postSchema);

// 血统排行榜模型
const bloodlineSchema = new mongoose.Schema({
    rank: { type: Number, required: true, unique: true },
    name: { type: String, required: true },
    bloodlineType: { type: String, required: true },
    purity: { type: Number, required: true },
    power: { type: Number, required: true },
    description: { type: String },
    updatedAt: { type: Date, default: Date.now },
    updatedBy: { type: String },
});

const Bloodline = mongoose.model('Bloodline', bloodlineSchema);

// ============ 认证中间件 ============

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: '未提供授权令牌' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: '令牌无效或已过期' });
    }
};

const verifySuperAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.role !== 'super_admin') {
            return res.status(403).json({ message: '仅超级管理员可执行此操作' });
        }
        next();
    });
};

const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
            return res.status(403).json({ message: '需要管理员权限' });
        }
        next();
    });
};

// ============ 用户管理API ============

app.post('/api/auth/init-super-admin', async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        if (userCount > 0) {
            return res.status(400).json({ message: '系统已初始化' });
        }

        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: '用户名和密码不能为空' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            role: 'super_admin',
            createdAt: new Date(),
        });

        await user.save();
        res.status(201).json({ message: '超级管理员创建成功' });
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: '用户名或密码错误' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: '用户名或密码错误' });
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                username: user.username,
                role: user.role,
            },
        });
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.post('/api/admin/create-user', verifySuperAdmin, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ message: '用户名和密码不能为空' });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: '用户名已存在' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            role: 'admin',
            createdBy: req.user.username,
        });

        await user.save();
        res.status(201).json({
            message: '管理员创建成功',
            user: {
                username: user.username,
                role: user.role,
            },
        });
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.get('/api/admin/users', verifySuperAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.delete('/api/admin/users/:userId', verifySuperAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ message: '用户不存在' });
        }

        if (user.role === 'super_admin') {
            return res.status(403).json({ message: '无法删除超级管理员' });
        }

        await User.findByIdAndDelete(req.params.userId);
        res.json({ message: '用户删除成功' });
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.put('/api/admin/users/:userId/reset-password', verifySuperAdmin, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword) {
            return res.status(400).json({ message: '新密码不能为空' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(req.params.userId, { password: hashedPassword });
        
        res.json({ message: '密码重置成功' });
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

// ============ 守夜人讨论区API ============

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.post('/api/posts', verifyAdmin, async (req, res) => {
    try {
        const { title, content } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ message: '标题和内容不能为空' });
        }

        const post = new Post({
            title,
            content,
            author: req.user.username,
            authorRole: req.user.role,
        });

        await post.save();
        res.status(201).json(post);
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.put('/api/posts/:postId', verifyAdmin, async (req, res) => {
    try {
        const post = await Post.findById(req.params.postId);
        
        if (!post) {
            return res.status(404).json({ message: '帖子不存在' });
        }

        if (post.author !== req.user.username && req.user.role !== 'super_admin') {
            return res.status(403).json({ message: '无权编辑此帖子' });
        }

        const { title, content } = req.body;
        if (title) post.title = title;
        if (content) post.content = content;
        post.updatedAt = new Date();

        await post.save();
        res.json(post);
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.delete('/api/posts/:postId', verifyAdmin, async (req, res) => {
    try {
        const post = await Post.findById(req.params.postId);
        
        if (!post) {
            return res.status(404).json({ message: '帖子不存在' });
        }

        if (post.author !== req.user.username && req.user.role !== 'super_admin') {
            return res.status(403).json({ message: '无权删除此帖子' });
        }

        await Post.findByIdAndDelete(req.params.postId);
        res.json({ message: '帖子删除成功' });
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

// ============ 血统排行榜API ============

app.get('/api/bloodline-ranking', async (req, res) => {
    try {
        const bloodlines = await Bloodline.find().sort({ rank: 1 });
        res.json(bloodlines);
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.post('/api/bloodline-ranking', verifyAdmin, async (req, res) => {
    try {
        const { rank, name, bloodlineType, purity, power, description } = req.body;
        
        if (!rank || !name || !bloodlineType || purity === undefined || power === undefined) {
            return res.status(400).json({ message: '缺少必要字段' });
        }

        const bloodline = new Bloodline({
            rank,
            name,
            bloodlineType,
            purity,
            power,
            description,
            updatedBy: req.user.username,
        });

        await bloodline.save();
        res.status(201).json(bloodline);
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.put('/api/bloodline-ranking/:bloodlineId', verifyAdmin, async (req, res) => {
    try {
        const { rank, name, bloodlineType, purity, power, description } = req.body;
        
        const bloodline = await Bloodline.findByIdAndUpdate(
            req.params.bloodlineId,
            {
                rank: rank || undefined,
                name: name || undefined,
                bloodlineType: bloodlineType || undefined,
                purity: purity !== undefined ? purity : undefined,
                power: power !== undefined ? power : undefined,
                description: description || undefined,
                updatedAt: new Date(),
                updatedBy: req.user.username,
            },
            { new: true }
        );

        if (!bloodline) {
            return res.status(404).json({ message: '血统不存在' });
        }

        res.json(bloodline);
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

app.delete('/api/bloodline-ranking/:bloodlineId', verifyAdmin, async (req, res) => {
    try {
        await Bloodline.findByIdAndDelete(req.params.bloodlineId);
        res.json({ message: '血统删除成功' });
    } catch (err) {
        res.status(500).json({ message: '服务器错误', error: err.message });
    }
});

// 健康检查端点
app.get('/health', (req, res) => {
    res.json({ status: 'OK', message: '服务器运行中' });
});

// ============ 服务器启动 ============

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
});

module.exports = app;
