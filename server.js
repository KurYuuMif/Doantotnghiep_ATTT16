import express from "express";
import multer from "multer";
import session from "express-session";
import bcrypt from "bcryptjs";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import { nanoid } from "nanoid";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

// Thiết lập __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Cấu hình app và database
const app = express();

const adapter = new JSONFile("db.json");
const defaultData = { users: [], files: [] };
const db = new Low(adapter, defaultData);
await db.read();
db.data ||= defaultData;

// Cấu hình view và static
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("public/uploads"));
app.use(express.static("public"));

app.use(session({
  secret: "drive-secret",
  resave: false,
  saveUninitialized: false
}));

// Cấu hình upload
const storage = multer.diskStorage({
  destination: "./public/uploads/",
  filename: (req, file, cb) => {
    const unique = Date.now() + "_" + file.originalname;
    cb(null, unique);
  }
});
const upload = multer({ storage });

// Middleware kiểm tra đăng nhập
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

// Routes
app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/dashboard");
  res.render("index");
});

app.get("/register", (req, res) => res.render("register"));

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.data.users.push({ id: nanoid(), username, password: hash });
  await db.write();
  res.redirect("/login");
});

app.get("/login", (req, res) => res.render("login"));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = db.data.users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user.id;
    res.redirect("/dashboard");
  } else {
    res.send("Sai tên đăng nhập hoặc mật khẩu");
  }
});

app.get("/dashboard", requireLogin, (req, res) => {
  const userFiles = db.data.files.filter(f => f.owner === req.session.userId);
  res.render("dashboard", { files: userFiles });
});

app.post("/upload", requireLogin, upload.single("file"), async (req, res) => {
  db.data.files.push({
    id: nanoid(),
    name: req.file.originalname,
    path: req.file.filename,
    owner: req.session.userId
  });
  await db.write();
  res.redirect("/dashboard");
});

app.get("/download/:filename", requireLogin, (req, res) => {
  const file = db.data.files.find(
    f => f.path === req.params.filename && f.owner === req.session.userId
  );
  if (!file) return res.send("Không tìm thấy file");
  res.download(path.join(__dirname, "public/uploads", file.path));
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Running on", port));
