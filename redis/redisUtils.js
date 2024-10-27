
const RATE_IN_SECONDS = 60
const incrementRedisKeys = async (redisClient, ipKey, deviceKey) => {
    try {
        await redisClient.incr(ipKey)
        await redisClient.incr(deviceKey)
        await redisClient.expire(ipKey, RATE_IN_SECONDS)
        await redisClient.expire(deviceKey, RATE_IN_SECONDS)
    } catch (error) {
        console.error("Error incrementing Redis keys:", error)
    }
}

const THRESHOLD_COUNT = 5
const BLOCKED_ACCESS_TIME_IN_SECONDS = 45
async function checkAndBlockIfLimitExceeded(redisClient, redisKeyIp, redisKeyDevice, blockedKeyIp, blockedKeyDevice) {
    try {
        const ipAttempts = await redisClient.get(redisKeyIp)
        const deviceAttempts = await redisClient.get(redisKeyDevice)
        if (ipAttempts >= THRESHOLD_COUNT || deviceAttempts >= THRESHOLD_COUNT) {
            // blockUntil value needed for future reference, 3rd param sets actual expiration
            const blockUntil = Date.now() + BLOCKED_ACCESS_TIME_IN_SECONDS * 1000 
            await redisClient.set(blockedKeyIp, blockUntil, { EX: BLOCKED_ACCESS_TIME_IN_SECONDS })
            await redisClient.set(blockedKeyDevice, blockUntil, { EX: BLOCKED_ACCESS_TIME_IN_SECONDS })
        }
    } catch (error) {
        console.error("Error in checkAndBlockIfLimitExceeded:", error)
        throw error
    }
}

module.exports = {
    incrementRedisKeys,
    checkAndBlockIfLimitExceeded
}