import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import axios from "axios";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("exchange.db");
const JWT_SECRET = "easy-exchange-secret-key"; // In production, use env var

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT, -- Optional for Google users
    googleId TEXT UNIQUE,
    email TEXT UNIQUE,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    imageUrl TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users (id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    itemId INTEGER NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(userId, itemId),
    FOREIGN KEY (userId) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (itemId) REFERENCES items (id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    itemId INTEGER NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (itemId) REFERENCES items (id) ON DELETE CASCADE
  );
`);

// Migrations
try { db.prepare("ALTER TABLE users ADD COLUMN googleId TEXT UNIQUE").run(); } catch (e) {}
try { db.prepare("ALTER TABLE users ADD COLUMN email TEXT UNIQUE").run(); } catch (e) {}
try { db.prepare("ALTER TABLE items ADD COLUMN userId INTEGER DEFAULT 1").run(); } catch (e) {}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

  // Auth Middleware
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "未登錄" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      req.userId = decoded.userId;
      next();
    } catch (err) {
      res.status(401).json({ error: "登錄過期" });
    }
  };

  db.exec(`
    UPDATE items SET status = 'active' WHERE status NOT IN ('active', 'done');
  `);

  // Simple Seeder
  const itemCount = (db.prepare("SELECT COUNT(*) as count FROM items").get() as any).count;
  if (itemCount === 0) {
    db.prepare(`
      INSERT INTO users (username, password) VALUES ('demo', '$2a$10$SomethingRandomToKeepStable')
    `).run();
    db.prepare(`
      INSERT INTO items (userId, title, description, price, imageUrl, category, status)
      VALUES 
      (1, 'iPhone 13 Pro', '九成新，電池健康度 90%，有盒有配件。', 4500, 'https://images.unsplash.com/photo-1632661674596-df8be070a5c5?auto=format&fit=crop&q=80&w=1000', '數碼產品', 'active'),
      (1, '現代經濟學原理', '大學教科書，近乎全新。', 150, 'https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?auto=format&fit=crop&q=80&w=1000', '書籍文具', 'active'),
      (1, '二手木製餐桌', '尺寸 120x80cm，穩固耐用。', 300, 'https://images.unsplash.com/photo-1577140917170-285929fb55b7?auto=format&fit=crop&q=80&w=1000', '家居生活', 'active')
    `).run();
  }

  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  // Auth Routes
  app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "請輸入帳號密碼" });
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const info = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run(username, hashedPassword);
      const token = jwt.sign({ userId: info.lastInsertRowid }, JWT_SECRET, { expiresIn: "7d" });
      res.json({ token, user: { id: info.lastInsertRowid, username } });
    } catch (error: any) {
      if (error.message.includes("UNIQUE")) return res.status(400).json({ error: "帳號已存在" });
      res.status(500).json({ error: "註冊失敗" });
    }
  });

  app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as any;
    if (!user || !user.password || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "帳號或密碼錯誤" });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { id: user.id, username: user.username } });
  });

  app.get("/api/me", authenticate, (req: any, res) => {
    const user = db.prepare("SELECT id, username, createdAt FROM users WHERE id = ?").get(req.userId);
    res.json(user);
  });

  // Favorites Routes
  app.post("/api/favorites/:itemId", authenticate, (req: any, res) => {
    const { itemId } = req.params;
    try {
      const existing = db.prepare("SELECT id FROM favorites WHERE userId = ? AND itemId = ?").get(req.userId, itemId);
      if (existing) {
        db.prepare("DELETE FROM favorites WHERE userId = ? AND itemId = ?").run(req.userId, itemId);
        res.json({ favorited: false });
      } else {
        db.prepare("INSERT INTO favorites (userId, itemId) VALUES (?, ?)").run(req.userId, itemId);
        res.json({ favorited: true });
      }
    } catch (error) {
      res.status(500).json({ error: "操作失敗" });
    }
  });

  app.get("/api/my-favorites", authenticate, (req: any, res) => {
    const items = db.prepare(`
      SELECT i.* FROM items i
      JOIN favorites f ON i.id = f.itemId
      WHERE f.userId = ?
      ORDER BY f.createdAt DESC
    `).all(req.userId);
    res.json(items);
  });

  // API Routes
  app.get("/api/items", (req, res) => {
    const { category } = req.query;
    try {
      let query = "SELECT * FROM items WHERE 1=1";
      const params = [];
      if (category && category !== "全部") {
        query += " AND category = ?";
        params.push(category);
      }
      query += " ORDER BY CASE WHEN status = 'active' THEN 0 ELSE 1 END, createdAt DESC";
      const items = db.prepare(query).all(...params);
      res.json(items);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch items" });
    }
  });

  app.get("/api/my-items", authenticate, (req: any, res) => {
    const items = db.prepare("SELECT * FROM items WHERE userId = ? ORDER BY createdAt DESC").all(req.userId);
    res.json(items);
  });

  app.post("/api/items", authenticate, (req: any, res) => {
    const { title, description, price, imageUrl, category, status } = req.body;
    try {
      const info = db.prepare(
        "INSERT INTO items (userId, title, description, price, imageUrl, category, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).run(req.userId, title, description, price, imageUrl, category, status || 'active');
      res.json({ id: info.lastInsertRowid });
    } catch (error) {
      res.status(500).json({ error: "Failed to create item" });
    }
  });

  app.patch("/api/items/:id/status", authenticate, (req: any, res) => {
    const { id } = req.params;
    const { status } = req.body;
    // Check ownership
    const item = db.prepare("SELECT userId FROM items WHERE id = ?").get(id) as any;
    if (!item || item.userId !== req.userId) return res.status(403).json({ error: "無權限" });
    
    db.prepare("UPDATE items SET status = ? WHERE id = ?").run(status, id);
    res.json({ success: true });
  });

  app.get("/api/items/:id/comments", (req, res) => {
    const comments = db.prepare("SELECT * FROM comments WHERE itemId = ? ORDER BY createdAt ASC").all(req.params.id);
    res.json(comments);
  });

  app.post("/api/items/:id/comments", (req, res) => {
    const { author, content } = req.body;
    const info = db.prepare("INSERT INTO comments (itemId, author, content) VALUES (?, ?, ?)").run(req.params.id, author, content);
    res.json({ id: info.lastInsertRowid });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
