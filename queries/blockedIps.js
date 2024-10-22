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

const isIpBlocked = async (ip_address) => {
    try {
        const result = await db.oneOrNone(
            `SELECT * FROM blocked_ips WHERE ip_address=$1 AND expiration_time > CURRENT_TIMESTAMP`,
            [ip_address]
        )
        return result
    } catch (err) {
        return { err: `${err}, sql query error - check if IP is blocked` }
    }
}

const getAllFailedAttemptsForIp = async (ip_address) => {
    try {
        const result = await db.any(
            `SELECT * FROM blocked_ips WHERE ip_address=$1 AND expiration_time > CURRENT_TIMESTAMP`
            [ip_address]
        )
        return result
    } catch (err) {
        return { err: `${err}, sql query error - get all failed attempts for IP` }
    }
}

module.exports = {
    isIpBlocked,
    getAllFailedAttemptsForIp,
    addBlockedIp,
    getBlockedIp
}