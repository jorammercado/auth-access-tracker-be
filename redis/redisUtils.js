

const incrementRedisKeys = async (redisClient, ipKey, deviceKey) => {
    try {
        await redisClient.incr(ipKey)
        await redisClient.incr(deviceKey)
        // expire 1 min
        await redisClient.expire(ipKey, 60)
        await redisClient.expire(deviceKey, 60) 
    } catch (error) {
        console.error("Error incrementing Redis keys:", error)
    }
}

module.exports = { incrementRedisKeys }