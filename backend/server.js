// ===============================
// Member 4 – Password Security
// SHA-256 Password Hashing
// ===============================

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const cors = require("cors");

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Connect to database
const db = new sqlite3.Database("database.db", (err) => {
    if (err) {
        console.log("Database connection error:", err.message);
    } else {
        console.log("Connected to SQLite database");
    }
});

// Create users table if not exists
db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
`);

// SHA-256 hashing function
function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

// ===============================
// REGISTER API
// ===============================
app.post("/api/register", (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({
            message: "Username and password required"
        });
    }

    // Hash password before storing
    const hashedPassword = hashPassword(password);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword],
        function (err) {

            if (err) {
                return res.json({
                    message: "User already exists"
                });
            }

            res.json({
                message: "Registration successful"
            });
        }
    );
});

// ===============================
// LOGIN API
// ===============================
app.post("/api/login", (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({
            message: "Username and password required"
        });
    }

    // Hash entered password
    const hashedPassword = hashPassword(password);

    db.get(
        "SELECT * FROM users WHERE username=? AND password=?",
        [username, hashedPassword],
        (err, row) => {

            if (err) {
                return res.json({
                    message: "Database error"
                });
            }

            if (row) {
                res.json({
                    message: "Login successful"
                });
            } else {
                res.json({
                    message: "Invalid username or password"
                });
            }
        }
    );
});

// ===============================
// SHOW USERS (for testing)
// ===============================
app.get("/api/users", (req, res) => {

    db.all(
        "SELECT username, password FROM users",
        (err, rows) => {

            if (err) {
                return res.json({
                    message: "Database error"
                });
            }

            res.json(rows);
        }
    );
});

// ===============================
// START SERVER
// ===============================
app.listen(5000, () => {
    console.log("Server running at http://localhost:5000");
});