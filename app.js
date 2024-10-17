const express = require("express")
const cors = require("cors")
const app = express()

app.use(cors())
app.use(express.json())

app.get("/", (req, res) => {
    res.send("Welcome to Red Canary Take Home Test.")
})

const usersController = require("./controllers/usersController")
app.use("/users", usersController)

app.get("*", (req, res) => {
    res.status(404).json({ success: false, data: { error: "Page not found." } })
})

module.exports = app