require('dotenv').config()

// redis client setup
const { createClient } = require('redis')

const redisClient = createClient({
  url: process.env.REDIS_URL,
  password: process.env.REDIS_PASSWORD
})

// need semicolon
redisClient.on('error', (err) => console.error('Redis Client Error', err));

(async () => {
  await redisClient.connect()
  console.log('Connected to Redis successfully')
})()

module.exports = redisClient
