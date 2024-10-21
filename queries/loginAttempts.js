const db = require("../db/dbConfig.js")

const createLoginAttempt = async (user_id, ip_address, success, device_fingerprint) => {
    try {
        const newLoginAttempt = await db.one(
            `INSERT INTO login_attempts (user_id, ip_address, success, device_fingerprint) ` +
            `VALUES ($1, $2, $3, $4) RETURNING *`,
            [user_id, ip_address, success, device_fingerprint]
        )
        return newLoginAttempt
    } catch (err) {
        return { err: `${err}, sql query error - add login attempt` }
    }
}


const getLoginAttemptsByUserId = async (user_id) => {
    try {
        const loginAttempts = await db.any(
            `SELECT * FROM login_attempts WHERE user_id=$1 ORDER BY attempt_time DESC`,
            [user_id]
        )
        return loginAttempts
    } catch (err) {
        return { err: `${err}, sql query error - get login attempts by user_id` }
    }
}


const getAllLoginAttempts = async () => {
    try {
        const allLoginAttempts = await db.any(
            `SELECT * FROM login_attempts ORDER BY attempt_time DESC`
        )
        return allLoginAttempts
    } catch (err) {
        return { err: `${err}, sql query error - get all login attempts` }
    }
}

const getLastThreeLoginAttempts = async (user_id) => {
    try {
        const attempts = await db.any(
            `SELECT * FROM login_attempts WHERE user_id=$1 ORDER BY attempt_time DESC LIMIT 3`,
            [user_id]
        )
        return attempts
    } catch (err) {
        return { err: `${err}, SQL query error - get last three login attempts` }
    }
}

module.exports = {
    getLastThreeLoginAttempts,
    createLoginAttempt,
    getLoginAttemptsByUserId,
    getAllLoginAttempts
}
