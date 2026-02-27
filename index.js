const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const DATA_DIR = path.join(__dirname, 'data');

// Admin email for password notifications
const ADMIN_EMAIL = 'wang_xuxuan@163.com';

// Email configuration
const emailTransporter = nodemailer.createTransport({
  service: '163',
  auth: {
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || '',
  },
});

// Send email helper
async function sendEmail(to, subject, html) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.log('Email not configured. Would send:');
    console.log('To:', to);
    console.log('Subject:', subject);
    console.log('Body:', html);
    return { success: false, message: 'Email not configured' };
  }

  try {
    const result = await emailTransporter.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject,
      html,
    });
    console.log('Email sent:', result.messageId);
    return { success: true, messageId: result.messageId };
  } catch (error) {
    console.error('Email send failed:', error);
    return { success: false, error: error.message };
  }
}

// Send password to admin
async function notifyAdminNewPassword(username, password, action = 'created') {
  const html = `
    <h2>计划系统 - 管理员密码通知</h2>
    <p>用户 <strong>${username}</strong> 已${action === 'created' ? '创建' : '重置密码'}。</p>
    <p><strong>账号:</strong> ${username}</p>
    <p><strong>密码:</strong> ${password}</p>
    <p><strong>时间:</strong> ${new Date().toLocaleString('zh-CN')}</p>
    <hr>
    <p style="color: #666; font-size: 12px;">此邮件由计划系统自动发送</p>
  `;

  return sendEmail(ADMIN_EMAIL, `计划系统 - ${username} 密码通知`, html);
}

// Send password reset email to user
async function sendPasswordResetEmail(email, username, resetToken) {
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password?token=${resetToken}`;
  
  const html = `
    <h2>计划系统 - 密码重置</h2>
    <p>您好 ${username}，</p>
    <p>您请求重置密码，请点击下方链接重置：</p>
    <p><a href="${resetUrl}" style="padding: 10px 20px; background: #4A90A4; color: white; text-decoration: none; border-radius: 5px;">重置密码</a></p>
    <p>或者复制以下链接到浏览器：</p>
    <p>${resetUrl}</p>
    <p>此链接将在 1 小时后失效。</p>
    <hr>
    <p style="color: #666; font-size: 12px;">如果您没有请求重置密码，请忽略此邮件。</p>
  `;

  return sendEmail(email, '计划系统 - 密码重置', html);
}

// Middleware
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? (process.env.ALLOWED_ORIGINS || '*').split(',')
    : true,
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// Request logging
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
  });
}

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (err) {
    console.error('Failed to create data directory:', err);
  }
}

// File paths
const getUsersFilePath = () => path.join(DATA_DIR, 'users.json');
const getUserDataFilePath = (userId) => path.join(DATA_DIR, `user_${userId}_data.json`);
const getResetTokensFilePath = () => path.join(DATA_DIR, 'reset_tokens.json');

// Initialize default admin user
async function initDefaultAdmin() {
  try {
    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      // File doesn't exist
    }

    // Check if admin exists
    const adminExists = users.find(u => u.role === 'admin');
    if (!adminExists) {
      const adminPassword = 'admin123'; // Fixed admin password
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      const adminUser = {
        id: 'admin_' + Date.now(),
        username: 'admin',
        email: ADMIN_EMAIL,
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date().toISOString(),
      };
      users.push(adminUser);
      await fs.writeFile(usersFile, JSON.stringify(users, null, 2));
      
      console.log('Default admin created. Username: admin, Password: admin123');
    }
  } catch (err) {
    console.error('Failed to init admin:', err);
  }
}

// Generate random password
function generateRandomPassword(length = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Routes

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // Update last login
    user.lastLoginAt = new Date().toISOString();
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2));

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: '请填写所有必填项' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: '请输入有效的邮箱地址' });
    }

    // Validate password strength
    if (password.length < 6) {
      return res.status(400).json({ error: '密码至少需要6个字符' });
    }

    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      // File doesn't exist
    }

    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: '用户名已被使用' });
    }

    if (users.find(u => u.email === email)) {
      return res.status(400).json({ error: '邮箱已被注册' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: 'user_' + Date.now(),
      username,
      email,
      password: hashedPassword,
      role: 'user',
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2));

    // Send welcome email
    const welcomeHtml = `
      <h2>欢迎使用计划系统</h2>
      <p>您好 ${username}，</p>
      <p>您的账号已成功创建！</p>
      <p><strong>用户名:</strong> ${username}</p>
      <p>您现在可以登录并开始使用计划系统了。</p>
      <hr>
      <p style="color: #666; font-size: 12px;">计划系统团队</p>
    `;
    await sendEmail(email, '欢迎使用计划系统', welcomeHtml);

    res.json({
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.createdAt,
      },
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Forgot password - request reset
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: '请输入邮箱地址' });
    }

    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.status(404).json({ error: '用户不存在' });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
      // Don't reveal if email exists
      return res.json({ message: '如果该邮箱已注册，重置链接将发送到您的邮箱' });
    }

    // Generate reset token
    const resetToken = uuidv4();
    const resetExpires = new Date();
    resetExpires.setHours(resetExpires.getHours() + 1);

    // Save reset token
    const tokensFile = getResetTokensFilePath();
    let tokens = {};
    try {
      const data = await fs.readFile(tokensFile, 'utf8');
      tokens = JSON.parse(data);
    } catch {
      // File doesn't exist
    }

    tokens[resetToken] = {
      userId: user.id,
      expires: resetExpires.toISOString(),
    };
    await fs.writeFile(tokensFile, JSON.stringify(tokens, null, 2));

    // Send reset email
    await sendPasswordResetEmail(email, user.username, resetToken);

    res.json({ message: '如果该邮箱已注册，重置链接将发送到您的邮箱' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password with token
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: '请提供重置令牌和新密码' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: '密码至少需要6个字符' });
    }

    // Verify token
    const tokensFile = getResetTokensFilePath();
    let tokens = {};
    try {
      const data = await fs.readFile(tokensFile, 'utf8');
      tokens = JSON.parse(data);
    } catch {
      return res.status(400).json({ error: '无效或已过期的重置链接' });
    }

    const tokenData = tokens[token];
    if (!tokenData || new Date(tokenData.expires) < new Date()) {
      return res.status(400).json({ error: '无效或已过期的重置链接' });
    }

    // Update user password
    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.status(500).json({ error: 'Server error' });
    }

    const user = users.find(u => u.id === tokenData.userId);
    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2));

    // Delete used token
    delete tokens[token];
    await fs.writeFile(tokensFile, JSON.stringify(tokens, null, 2));

    // Notify admin
    await notifyAdminNewPassword(user.username, newPassword, '通过重置链接修改');

    res.json({ message: '密码重置成功' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password (authenticated)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: '请提供当前密码和新密码' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: '新密码至少需要6个字符' });
    }

    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.status(500).json({ error: 'Server error' });
    }

    const user = users.find(u => u.id === req.user.userId);
    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }

    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: '当前密码错误' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2));

    // Notify admin if admin user
    if (user.role === 'admin') {
      await notifyAdminNewPassword(user.username, newPassword, '自行修改');
    }

    res.json({ message: '密码修改成功' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.json([]);
    }

    // Remove password from response
    const safeUsers = users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt,
    }));

    res.json(safeUsers);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.status(404).json({ error: 'User not found' });
    }

    users = users.filter(u => u.id !== userId);
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2));

    // Delete user data file
    try {
      await fs.unlink(getUserDataFilePath(userId));
    } catch {
      // File might not exist
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset user password (admin only)
app.post('/api/admin/users/:userId/reset-password', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { newPassword } = req.body;

    if (!newPassword) {
      return res.status(400).json({ error: 'New password required' });
    }

    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users.find(u => u.id === userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2));

    // Notify admin
    await notifyAdminNewPassword(user.username, newPassword, '被管理员重置');

    res.json({ success: true });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user data
app.get('/api/data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const dataFile = getUserDataFilePath(userId);

    let data = { daily: {}, weekly: {}, monthly: {} };
    try {
      const fileData = await fs.readFile(dataFile, 'utf8');
      data = JSON.parse(fileData);
    } catch {
      // File doesn't exist, return empty data
    }

    res.json(data);
  } catch (err) {
    console.error('Get data error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save user data
app.post('/api/data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const dataFile = getUserDataFilePath(userId);

    const data = {
      ...req.body,
      lastUpdated: new Date().toISOString(),
    };

    await fs.writeFile(dataFile, JSON.stringify(data, null, 2));
    res.json({ success: true });
  } catch (err) {
    console.error('Save data error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users data (admin only)
app.get('/api/admin/all-data', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.json([]);
    }

    const allData = [];
    for (const user of users) {
      if (user.role === 'admin') continue;
      
      const dataFile = getUserDataFilePath(user.id);
      let userData = { daily: {}, weekly: {}, monthly: {} };
      try {
        const fileData = await fs.readFile(dataFile, 'utf8');
        userData = JSON.parse(fileData);
      } catch {
        // File doesn't exist
      }

      allData.push({
        userId: user.id,
        username: user.username,
        data: userData,
      });
    }

    res.json(allData);
  } catch (err) {
    console.error('Get all data error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Generate summary report
app.post('/api/admin/report', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userIds, dateRange, includeAll = false } = req.body;
    const { startDate, endDate } = dateRange;

    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.json([]);
    }

    const reports = [];
    const targetUsers = includeAll 
      ? users.filter(u => u.role !== 'admin')
      : users.filter(u => userIds.includes(u.id));

    for (const user of targetUsers) {
      const dataFile = getUserDataFilePath(user.id);
      let userData = { daily: {}, weekly: {}, monthly: {} };
      try {
        const fileData = await fs.readFile(dataFile, 'utf8');
        userData = JSON.parse(fileData);
      } catch {
        // No data
      }

      // Filter daily plans by date range
      const dailyPlans = Object.entries(userData.daily || {})
        .filter(([date]) => date >= startDate && date <= endDate)
        .map(([, plan]) => plan);

      // Calculate daily stats
      let totalDailyTasks = 0;
      let completedDailyTasks = 0;
      const moodScores = [];
      const highlights = [];
      const lessons = [];

      dailyPlans.forEach((plan) => {
        const allTasks = [
          plan.coreTask,
          ...plan.importantTasks,
          ...plan.otherTasks,
          ...plan.bottomLineTasks,
        ].filter(Boolean);

        totalDailyTasks += allTasks.length;
        completedDailyTasks += allTasks.filter((t) => t.completed).length;

        if (plan.reflection?.moodScore > 0) {
          moodScores.push(plan.reflection.moodScore);
        }
        if (plan.reflection?.highlight) {
          highlights.push(plan.reflection.highlight);
        }
        if (plan.reflection?.lesson) {
          lessons.push(plan.reflection.lesson);
        }
      });

      // Weekly stats
      const weeklyPlans = Object.entries(userData.weekly || {})
        .filter(([weekStart]) => weekStart >= startDate && weekStart <= endDate)
        .map(([, plan]) => plan);

      let totalWeeklyGoals = 0;
      let completedWeeklyGoals = 0;
      weeklyPlans.forEach((plan) => {
        const goals = [...plan.lifeGoals, ...plan.workGoals].filter(Boolean);
        totalWeeklyGoals += goals.length;
        completedWeeklyGoals += goals.filter((g) => g.completed).length;
      });

      // Monthly stats
      const monthlyPlans = Object.entries(userData.monthly || {})
        .filter(([month]) => {
          const monthStart = month + '-01';
          return monthStart >= startDate && monthStart <= endDate;
        })
        .map(([, plan]) => plan);

      let totalMonthlyGoals = 0;
      let completedMonthlyGoals = 0;
      monthlyPlans.forEach((plan) => {
        const goals = [...plan.lifeGoals, ...plan.workGoals].filter(Boolean);
        totalMonthlyGoals += goals.length;
        completedMonthlyGoals += goals.filter((g) => g.completed).length;
      });

      reports.push({
        userId: user.id,
        username: user.username,
        dateRange: { startDate, endDate },
        dailyTasks: {
          total: totalDailyTasks,
          completed: completedDailyTasks,
          completionRate: totalDailyTasks > 0 ? Math.round((completedDailyTasks / totalDailyTasks) * 100) : 0,
          planCount: dailyPlans.length,
        },
        weeklyGoals: {
          total: totalWeeklyGoals,
          completed: completedWeeklyGoals,
          completionRate: totalWeeklyGoals > 0 ? Math.round((completedWeeklyGoals / totalWeeklyGoals) * 100) : 0,
          planCount: weeklyPlans.length,
        },
        monthlyGoals: {
          total: totalMonthlyGoals,
          completed: completedMonthlyGoals,
          completionRate: totalMonthlyGoals > 0 ? Math.round((completedMonthlyGoals / totalMonthlyGoals) * 100) : 0,
          planCount: monthlyPlans.length,
        },
        reflections: {
          averageMoodScore: moodScores.length > 0 
            ? Math.round((moodScores.reduce((a, b) => a + b, 0) / moodScores.length) * 10) / 10 
            : 0,
          highlights: highlights.slice(0, 10),
          lessons: lessons.slice(0, 10),
        },
      });
    }

    res.json({
      generatedAt: new Date().toISOString(),
      dateRange: { startDate, endDate },
      reports,
    });
  } catch (err) {
    console.error('Generate report error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get admin stats
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const usersFile = getUsersFilePath();
    let users = [];
    try {
      const data = await fs.readFile(usersFile, 'utf8');
      users = JSON.parse(data);
    } catch {
      return res.json({
        totalUsers: 0,
        totalDailyPlans: 0,
        totalWeeklyPlans: 0,
        totalMonthlyPlans: 0,
        usersWithData: [],
      });
    }

    const regularUsers = users.filter(u => u.role !== 'admin');
    let totalDailyPlans = 0;
    let totalWeeklyPlans = 0;
    let totalMonthlyPlans = 0;
    const usersWithData = [];

    for (const user of regularUsers) {
      const dataFile = getUserDataFilePath(user.id);
      try {
        const fileData = await fs.readFile(dataFile, 'utf8');
        const userData = JSON.parse(fileData);
        const dailyCount = Object.keys(userData.daily || {}).length;
        const weeklyCount = Object.keys(userData.weekly || {}).length;
        const monthlyCount = Object.keys(userData.monthly || {}).length;

        totalDailyPlans += dailyCount;
        totalWeeklyPlans += weeklyCount;
        totalMonthlyPlans += monthlyCount;

        if (dailyCount > 0 || weeklyCount > 0 || monthlyCount > 0) {
          usersWithData.push({
            userId: user.id,
            username: user.username,
            dailyPlans: dailyCount,
            weeklyPlans: weeklyCount,
            monthlyPlans: monthlyCount,
          });
        }
      } catch {
        // No data file
      }
    }

    res.json({
      totalUsers: regularUsers.length,
      totalDailyPlans,
      totalWeeklyPlans,
      totalMonthlyPlans,
      usersWithData,
    });
  } catch (err) {
    console.error('Get stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
async function start() {
  await ensureDataDir();
  await initDefaultAdmin();
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API URL: http://localhost:${PORT}/api`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
  });
}

start().catch(console.error);
