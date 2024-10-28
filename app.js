const express = require("express")
const cors = require("cors")
const app = express()

app.use(cors())
app.use(express.json())

// route to test redis connection
app.get('/redis-test', async (req, res) => {
    try {
        const redisClient = require('./redis/redisClient')
        await redisClient.set('testKey-value-sent', 'Hello from Redis!')
        const value = await redisClient.get('testKey-value-sent')
        res.send(`Redis response: ${value}`)
    } catch (error) {
        console.error('Redis error:', error)
        res.status(500).send('Error connecting to Redis.')
    }
})

app.get("/", (req, res) => {
    res.send("Welcome to Red Canary Take Home Test.")
})

const usersController = require("./controllers/usersController")
app.use("/users", usersController)

const authController = require("./controllers/authController")
app.use("/auth", authController)

app.get("*", (req, res) => {
    res.status(404).json({ success: false, data: { error: "Page not found." } })
})

module.exports = app