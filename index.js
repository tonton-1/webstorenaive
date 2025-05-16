const cors = require("cors");
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://127.0.0.1:5500", // หรือ URL ของ frontend ที่จะเรียก
    credentials: true,
  })
);

app.use(cookieParser());

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  })
);

const port = 8000;
const secret = "mysecret";

let conn = null;

// function init connection mysql
const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "tutorial",
  });
};

/* เราจะแก้ไข code ที่อยู่ตรงกลาง */
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const passwordHash = await bcrypt.hash(password, 10);
    const userData = {
      email,
      password: passwordHash,
    };

    const [result] = await conn.query("INSERT INTO users (email, password) VALUES (?, ?)", [userData.email, userData.password]);
    res.json({
      message: "User registered successfully",
    });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({
      message: error,
    });
  }
});
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const [result] = await conn.query("SELECT * FROM users WHERE email = ?", [email]);
    const userData = result[0];
    if (!userData) {
      res.json({
        message: "Login Failed",
      });
      return false;
    }
    const match = await bcrypt.compare(password, userData.password);
    if (!match) {
      res.json({
        message: "Login Failed",
      });
      return false;
    }

    // สร้าง jwt token
    const token = jwt.sign({ email, role: "user" }, secret, { expiresIn: "1h" });

    res.json({
      message: "Login successful",
      token,
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(401).json({
      message: error,
    });
  }
});

app.get("/api/user", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];

    let authToken = "";
    if (authHeader) {
      authToken = authHeader.split(" ")[1];
    }
    console.log("authToken", authToken);
    const user = jwt.verify(authToken, secret);
    console.log("user", user);

    const [checkresult] = await conn.query("SELECT * FROM users where email = ?", user.email);

    if (!checkresult[0]) {
      throw { message: "User not found" };
    }
    const [result] = await conn.query("SELECT * FROM users");
    res.json({
      user: result,
    });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({
      message: "Authentication failed",
      error,
    });
  }
});
// Listen
app.listen(port, async () => {
  await initMySQL();
  console.log("Server started at port 8000");
});
