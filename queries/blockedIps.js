const db = require("../db/dbConfig.js")

const addBlockedIp = async (ip_address, block_expiration, user_id) => {
    try {
        await db.none(
            `INSERT INTO blocked_ips (ip_address, block_expiration, user_id)
             VALUES ($1, $2, $3)`,
            [ip_address, block_expiration, user_id]
        )
        return { success: true }
    } catch (err) {
        return { err: `${err}, SQL query error - add blocked IP` }
    }
}

const getBlockedIp = async (ip_address) => {
    try {
        const blockedIp = await db.oneOrNone(
            `SELECT * FROM blocked_ips WHERE ip_address=$1`,
            [ip_address]
        )
        return blockedIp
    } catch (err) {
        return { err: `${err}, SQL query error - get blocked IP` }
    }
}

module.exports = {
    addBlockedIp,
    getBlockedIp
}