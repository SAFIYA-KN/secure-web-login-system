const express = require("express")
const sqlite3 = require("sqlite3").verbose()
const crypto = require("crypto")
const cors = require("cors")

const app = express()

// middleware
app.use(express.json())
app.use(cors())

// connect database
const db = new sqlite3.Database("database.db", (err) => {
    if (err) {
        console.log("Database connection error")
    } else {
        console.log("Connected to database")
    }
})

// create users table
db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
`)

// SHA-256 hashing function
function hashPassword(password) {
    return crypto.createHash("sha256").update(password).digest("hex")
}

//
// REGISTER API
//
app.post("/register", (req, res) => {

    const { username, password } = req.body

    if (!username || !password) {
        return res.json({ message: "Username and password required" })
    }

    const hashedPassword = hashPassword(password)

    db.run(
        "INSERT INTO users(username,password) VALUES (?,?)",
        [username, hashedPassword],
        function(err) {

            if (err) {
                return res.json({ message: "User already exists" })
            }

            res.json({
                message: "Registration successful"
            })
        }
    )
})

//
// LOGIN API
//
app.post("/login", (req, res) => {

    const { username, password } = req.body

    const hashedPassword = hashPassword(password)

    db.get(
        "SELECT * FROM users WHERE username=? AND password=?",
        [username, hashedPassword],
        (err, row) => {

            if (row) {
                res.json({
                    message: "Login successful"
                })
            } else {
                res.json({
                    message: "Invalid username or password"
                })
            }
        }
    )
})

//
// SHOW USERS (for demo purpose)
//
app.get("/users", (req, res) => {

    db.all("SELECT username,password FROM users", (err, rows) => {

        if (err) {
            return res.json({ error: "Database error" })
        }

        res.json(rows)
    })
})

//
// START SERVER
//
app.listen(5000, () => {
    console.log("Server running on http://localhost:5000")
})