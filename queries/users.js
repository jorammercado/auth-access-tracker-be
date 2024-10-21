const db = require("../db/dbConfig.js")
const bcrypt = require("bcryptjs")

const getOneUser = async (id) => {
    try {
        const oneUser = await db.one(`SELECT * FROM users WHERE user_id=$1`, id)
        return oneUser
    } catch (err) {
        return { err: `${err}, sql query error - get one user` }
    }
}

const getAllUsers = async () => {
    try {
        const allUsers = await db.any(`SELECT * FROM users`)
        return allUsers
    }
    catch (err) {
        return { err: `${err}, sql query error - get all users` }
    }
}

const getOneUserByEmail = async ( email ) => {
    try {
        const oneUser = await db.oneOrNone("SELECT * FROM users WHERE email=$1",
            email)
        return oneUser
    }
    catch (err) {
        return { err: `${err}, sql query error - get one user by email` }
    }
}

const getOneUserByUserName = async ({ username }) => {
    try {
        const oneUser = await db.oneOrNone("SELECT * FROM users WHERE username=$1",
            username)
        return oneUser
    }
    catch (err) {
        return { err: `${err}, sql query error - get one user by username` }
    }
}

const createUser = async (user) => {
    try {
        const createdUser = await db.one(`INSERT INTO users (firstname,` +
            ` lastname,` +
            ` email,` +
            ` password,` +
            ` username,` +
            ` profile_img,` +
            ` about,` +
            ` dob) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [user.firstname,
            user.lastname,
            user.email,
            user.password,
            user.username,
            user.profile_img,
            user.about,
            user.dob])
        return createdUser
    }
    catch (err) {
        return { err: `${err}, sql query error - create user` }
    }
}

const deleteUserByUsername = async (username) => {
    try {
        const deletedUser = await db.one(
            `DELETE FROM users WHERE username=$1 RETURNING *`,
            username
        )
        return deletedUser
    }
    catch (err) {
        return { err: `${err}, sql query error in deleting a user` }
    }
}

const deleteUser = async (user_id) => {
    try {
        const deletedUser = await db.one(
            `DELETE FROM users WHERE user_id=$1 RETURNING *`,
            user_id
        )
        return deletedUser
    }
    catch (err) {
        return { err: `${err}, sql query error in deleting a user` }
    }
}

const updateUser = async (user_id, user) => {
    try {
        const { firstname, lastname, profile_img, about, dob, username, email } = user
        const updatedUser = await db.one(
            `UPDATE users SET firstname=$1, lastname=$2, ` +
            `profile_img=$3, about=$4, dob=$5, username=$6, email=$7 WHERE user_id=$8 ` +
            `RETURNING *`,
            [firstname, lastname, profile_img, about, dob, username, email, user_id]
        )
        return updatedUser
    }
    catch (err) {
        return { err: `${err}, sql query error in updating a user` }
    }
}

const updateUserPassword = async (user_id, password) => {
    try {
        const updatedUser = await db.one(
            `UPDATE users SET password=$1 WHERE user_id=$2 RETURNING *`,
            [password, user_id]
        )
        return updatedUser
    }
    catch (err) {
        return { err: `${err}, SQL query error in updating user password` }
    }
}

const updateUserResetToken = async (user_id, hashedToken, expirationTime) => {
    try {
        await db.none(
            `UPDATE users SET reset_token=$1, reset_token_expiration=$2 WHERE user_id=$3`,
            [hashedToken, expirationTime, user_id]
        )
        return { success: true }
    }
    catch (err) {
        return { err: `${err}, SQL query error in updating user reset token` }
    }
}

const getUserByResetToken = async (token) => {
    try {
        
        const user = await db.oneOrNone(
            `SELECT * FROM users WHERE reset_token IS NOT NULL AND reset_token_expiration > NOW()`
        );

        if (!user?.reset_token) {
            return null
        }

        const isMatch = await bcrypt.compare(token, user.reset_token)

        if (isMatch) {
            return user
        } else {
            return null
        }
    } catch (err) {
        return { err: `${err}, sql query error in getting user by reset token` }
    }
}

const updateUserMfaOtp = async (user_id, hashedOtp, expirationTime) => {
    try {
        await db.none(
            `UPDATE users SET mfa_otp=$1, mfa_otp_expiration=$2 WHERE user_id=$3`,
            [hashedOtp, expirationTime, user_id]
        )
    } catch (err) {
        console.error("Error updating user MFA OTP:", err)
        throw err
    }
}


module.exports = {
    updateUserMfaOtp,
    getUserByResetToken,
    updateUserResetToken,
    updateUserPassword,
    getOneUser,
    getAllUsers,
    getOneUserByEmail,
    getOneUserByUserName,
    createUser,
    deleteUserByUsername,
    deleteUser,
    updateUser
}