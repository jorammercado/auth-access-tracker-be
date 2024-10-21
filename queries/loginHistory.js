const db = require("../db/dbConfig.js")

const createLoginHistory = async (user_id, ip_address, device_fingerprint) => {
    try {
        const newLoginHistory = await db.one(
            `INSERT INTO login_history (user_id, ip_address, device_fingerprint) ` +
            `VALUES ($1, $2, $3) RETURNING *`,
            [user_id, ip_address, device_fingerprint]
        )
        return newLoginHistory
    } catch (err) {
        return { err: `${err}, sql query error - add login history` }
    }
}

const getLoginHistoryByUserId = async (user_id) => {
    try {
        const loginHistory = await db.any(
            `SELECT * FROM login_history WHERE user_id=$1 ORDER BY login_time DESC`,
            [user_id]
        )
        return loginHistory
    } catch (err) {
        return { err: `${err}, sql query error - get login history by user_id` }
    }
}

const getAllLoginHistory = async () => {
    try {
        const allLoginHistory = await db.any(
            `SELECT * FROM login_history ORDER BY login_time DESC`
        )
        return allLoginHistory
    } catch (err) {
        return { err: `${err}, sql query error - get all login history` }
    }
}

module.exports = {
    createLoginHistory,
    getLoginHistoryByUserId,
    getAllLoginHistory
}
