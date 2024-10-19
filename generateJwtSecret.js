const crypto = require('crypto')
const fs = require('fs')

const JWT_SECRET = crypto.randomBytes(64).toString('hex')

// write the key to the .env file
fs.appendFileSync('.env', `\nJWT_SECRET=${JWT_SECRET}`)

console.log('JWT secret has been generated and written to .env file.')
