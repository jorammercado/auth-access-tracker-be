const app = require("./app.js")

require("dotenv").config()

const PORT = process.env.PORT 

app.listen(PORT, () => {
    console.log(`Authentication and Access Tracking System Live on Port: ${PORT}`)
})