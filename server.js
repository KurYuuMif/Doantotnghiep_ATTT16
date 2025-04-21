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

import nodemailer from "nodemailer";
import otpGenerator from "otp-generator";
import speakeasy from "speakeasy"; 
import QRCode from "qrcode";       

import nodemailer from "nodemailer";

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
  db.data.users.push({
    id: nanoid(),
    username,
    password: hash,
    email: null,
    otpEnabled: false,
    otpSecret: null
  });
  await db.write();
  res.redirect("/login");
});

app.get("/login", (req, res) => res.render("login"));

app.post("/login", async (req, res) => {
  const { username, password, token } = req.body;
  const user = db.data.users.find(u => u.username === username);
  
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.send("Sai tên đăng nhập hoặc mật khẩu");
  }

  if (user.otpEnabled) {
    if (!token) {
      return res.render("otp-email", { username }); // tạo file này
    }
  
    if (token !== user.pendingOtp) {
      return res.send("Mã OTP không đúng.");
    }
  
    user.pendingOtp = null; // xóa OTP sau khi xác thực
    await db.write();
  }  

  req.session.userId = user.id;
  res.redirect("/dashboard");
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

app.get("/settings", requireLogin, (req, res) => {
  const user = db.data.users.find(u => u.id === req.session.userId);
  res.render("settings", { user });
});

app.post("/settings/email", requireLogin, async (req, res) => {
  const { email } = req.body;
  const user = db.data.users.find(u => u.id === req.session.userId);
  user.email = email;
  await db.write();
  res.redirect("/settings");
});

app.post("/settings/enable-otp", requireLogin, async (req, res) => {
  const user = db.data.users.find(u => u.id === req.session.userId);

  if (!user.email) {
    return res.send("Bạn cần thêm email trước khi bật OTP.");
  }

  // Tạo OTP ngẫu nhiên
  const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, specialChars: false });

  // Lưu tạm OTP để xác minh
  user.pendingOtp = otp;

  // Cấu hình mail (dùng dotenv để giấu thông tin)
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: `"OTP System" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: "Mã xác minh OTP",
    text: `Mã OTP của bạn là: ${otp}`
  });

  await db.write();

  // Hiện form để nhập mã OTP
  res.render("verify-otp-code");
});

app.post("/settings/disable-otp", requireLogin, async (req, res) => {
  const user = db.data.users.find(u => u.id === req.session.userId);
  user.otpEnabled = false;
  user.otpSecret = null;
  await db.write();
  res.redirect("/settings");
});

app.post("/delete/:id", requireLogin, async (req, res) => {
  const fileIndex = db.data.files.findIndex(f => f.id === req.params.id && f.owner === req.session.userId);
  if (fileIndex === -1) return res.send("Không tìm thấy file để xóa");

  const file = db.data.files[fileIndex];
  const filePath = path.join(__dirname, "public/uploads", file.path);

  // Xóa file khỏi ổ đĩa
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  // Xóa file khỏi database
  db.data.files.splice(fileIndex, 1);
  await db.write();

  res.redirect("/dashboard");
});

app.post("/settings/verify-otp", requireLogin, async (req, res) => {
  const { otp } = req.body;
  const user = db.data.users.find(u => u.id === req.session.userId);

  if (user.pendingOtp === otp) {
    user.otpEnabled = true;
    user.pendingOtp = null;
    await db.write();
    return res.send("Xác minh thành công. OTP đã bật!");
  }

  res.send("Mã OTP không chính xác.");
});


// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Running on", port));
