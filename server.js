const app = require("./app.js")

require("dotenv").config()

const PORT = process.env.PORT 

app.listen(PORT, () => {
    console.log(`Red Canary Take Home Test Live on Port: ${PORT}`)
})