const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const redisClient = require('../redis/redisClient.js')

const {
    getOneUserByEmail,
    getOneUser,
    createUser,
    deleteUser,
    updateUser,
    updateUserPassword,
    updateUserMfaOtp
} = require("../queries/users.js")

const {
    checkUsernameProvided,
    checkEmailProvided,
    checkPasswordProvided,
    checkUserIndex,
    checkUsernameExists,
    checkEmailExists,
    checkUsernameExistsOtherThanSelf,
    checkEmailExistsOtherThanSelf,
    checkEmailFormat,
    checkFirstnameLettersOnly,
    checkLastnameLettersOnly,
    checkUsernameValidity,
    checkDobFormat,
    checkNewPasswordProvided,
    checkPasswordStrength
} = require("../validations/checkUser.js")
const { setDefaultValues, verifyToken } = require("../middleware/utilityMiddleware.js")

const { createLoginAttempt, getLastThreeLoginAttempts } = require("../queries/loginAttempts.js")
const { createLoginHistory, getLoginHistoryByUserId } = require("../queries/loginHistory.js")
const { isIpBlocked,
    addBlockedIp,
    getLastSevenAttemptsForIp,
    updateBlockedIpExpiration } = require("../queries/blockedIps.js")

const transporter = require('../email/emailTransporter.js')
const createMailOptions = require("../email/mailOptions.js")
const { incrementRedisKeys, checkAndBlockIfLimitExceeded } = require('../redis/redisUtils')

const calculateRemainingTime = require('../utils/timeUtils.js')

const THIRTY_SECONDS_IN_MS = 30 * 1000
const IP_BASED_BLOCKING_LIMIT = 7
const OTP_EXPIRATION_MS = 1 * 60 * 1000 // 1 minutes
const MAX_FAILED_ATTEMPTS = 3

const users = express.Router()
const JWT_SECRET = process.env.JWT_SECRET

// standard login route
users.post("/login", checkEmailProvided, checkPasswordProvided, async (req, res) => {
    try {
        let oneUser = await getOneUserByEmail(req.body)
        if (!oneUser) {
            return res.status(404).json({ error: `user with ${req.body.email} email not found!` })
        }

        const isMatch = await bcrypt.compare(req.body.password, oneUser.password)
        if (!isMatch) {
            return res.status(400).json({
                error: "incorrect password and/or email",
                status: "Login Failure",
                login: false
            })
        }

        const token = jwt.sign(
            {
                user_id: oneUser.user_id,
                email: oneUser.email,
                username: oneUser.username
            },
            JWT_SECRET,
            { expiresIn: '10m' }
        )

        oneUser.password = "***************"
        res.status(200).json({ status: "Login Success", login: true, token, oneUser })
    } catch (error) {
        res.status(500).json({ error: error })
    }
})

// login route with multi factor authentication
users.post("/login-initiate", checkEmailProvided, checkPasswordProvided, async (req, res) => {
    try {
        let oneUser = await getOneUserByEmail(req.body.email)
        const ip_address = req.ip
        const device_fingerprint = req.headers['user-agent'] || "unknown"
        const redisKeyIp = `login_attempts:ip:${ip_address}`
        const redisKeyDevice = `login_attempts:device:${device_fingerprint}`
        const blockedKeyIp = `blocked:ip:${ip_address}`
        const blockedKeyDevice = `blocked:device:${device_fingerprint}`

        // check if IP or device is already blocked by Redis (rate blocking)
        let ipBlockedByRedis, deviceBlockedByRedis
        try {
            ipBlockedByRedis = await redisClient.get(`blocked:ip:${ip_address}`)
            deviceBlockedByRedis = await redisClient.get(`blocked:device:${device_fingerprint}`)
        } catch (error) {
            console.error("Error accessing Redis for blocked IP/device:", error)
            return res.status(500).json({ error: "An error occurred while verifying access. Please try again later." })
        }
        if (ipBlockedByRedis || deviceBlockedByRedis) {
            const blockedUntil = parseInt(ipBlockedByRedis || deviceBlockedByRedis)

            if (isNaN(blockedUntil))
                return res.status(500).json({ error: "An error occurred while verifying access. Please try again later." })

            const remainingTime = blockedUntil - Date.now()
            const { remainingMinutes, remainingSeconds } = calculateRemainingTime(remainingTime)
            return res.status(403).json({
                error: `Your IP or Device is blocked due to RATE LIMITS. Please try again after ${remainingMinutes} `
                    + `minutes and ${remainingSeconds} seconds.`
            })
        }

        // ip based blocking after 10 failed logins - (different/multiple user accounts used)
        // not handled/maintained by redis
        const ipBlockedInfo = await isIpBlocked(ip_address)
        if (ipBlockedInfo) {
            const remainingTime = new Date(ipBlockedInfo.block_expiration) - new Date()
            const { remainingMinutes, remainingSeconds } = calculateRemainingTime(remainingTime)
            return res.status(403).json({
                error: `Your IP is blocked due to multiple failed login attempts. Please try again after ${remainingMinutes} minutes ` +
                    ` and ${remainingSeconds} seconds.`
            })
        }

        if (!oneUser?.email) {
            // failed login attempt from unknown user for ip-based tracking and blocking
            const defaultUser = await getOneUserByEmail('unknown@domain.com')
            await createLoginAttempt(defaultUser.user_id, ip_address, false, device_fingerprint)

            // ip based blocking documentation - not rate blocking - (if different/multiple user accounts used)
            const last7Attempts = await getLastSevenAttemptsForIp(ip_address)
            if (last7Attempts?.filter(e => e.success === false)?.length >= IP_BASED_BLOCKING_LIMIT) {
                const expirationTimeIPBlocking = new Date(Date.now() + THIRTY_SECONDS_IN_MS) 
                await addBlockedIp(ip_address, expirationTimeIPBlocking, defaultUser.user_id)
            }

            // redis rate blocking documenation before returning
            await incrementRedisKeys(redisClient, redisKeyIp, redisKeyDevice)

            // block ip and/or device if rate limit has been exceeded
            await checkAndBlockIfLimitExceeded(redisClient, redisKeyIp, redisKeyDevice, blockedKeyIp, blockedKeyDevice)

            return res.status(404).json({ error: `User with ${req.body.email} email not found!` })
        }

        // check last 3 login attempts - account blocking for 3 consecutive fails
        const recentAttempts = await getLastThreeLoginAttempts(oneUser.user_id)
        if (recentAttempts?.err) {
            return res.status(500).json({
                error: "An error occurred while retrieving recent " +
                    "login attempts. Please try again later. " +
                    `${recentAttempts?.err}`
            })
        }
        const failedAttempts = recentAttempts.filter(attempt => !attempt.success)
        if (failedAttempts.length >= MAX_FAILED_ATTEMPTS) {
            const lastAttemptTime = new Date(failedAttempts[0].attempt_time)
            const currentTime = new Date()

            if (currentTime - lastAttemptTime < THIRTY_SECONDS_IN_MS) {
                await createLoginAttempt(oneUser.user_id, ip_address, false, device_fingerprint)
                const mailOptions = createMailOptions(oneUser.email, "Account Locked Due to Multiple Failed Login Attempts",
                    "Your account has been locked due to multiple failed login " +
                    "attempts. Login access will be restored after 30 seconds. If this " +
                    "wasn't you, please contact support immediately."
                )

                try {
                    await transporter.sendMail(mailOptions)
                } catch (error) {
                    console.error("Failed to send account lock email:", error)
                }

                // ip based blocking documentation - not rate blocking - (if different/multiple user accounts used)
                const last7Attempts = await getLastSevenAttemptsForIp(ip_address)
                if (last7Attempts?.filter(e => e.success === false)?.length >= IP_BASED_BLOCKING_LIMIT) {
                    const expirationTimeIPBlocking = new Date(Date.now() + THIRTY_SECONDS_IN_MS) 
                    await addBlockedIp(ip_address, expirationTimeIPBlocking, oneUser.user_id)
                }

                // redis rate blocking documenation before returning
                await incrementRedisKeys(redisClient, redisKeyIp, redisKeyDevice)

                // block ip and/or device if rate limit has been exceeded
                await checkAndBlockIfLimitExceeded(redisClient, redisKeyIp, redisKeyDevice, blockedKeyIp, blockedKeyDevice)

                return res.status(403).json({
                    error: "Account locked due to multiple " +
                        "failed login attempts. Please try again later."
                })
            }
        }


        const isMatch = await bcrypt.compare(req.body.password, oneUser.password)
        if (!isMatch) {
            await createLoginAttempt(oneUser.user_id, ip_address, false, device_fingerprint)

            // ip based blocking documentation - not rate blocking - (if different/multiple user accounts used)
            const last7Attempts = await getLastSevenAttemptsForIp(ip_address)
            if (last7Attempts?.filter(e => e.success === false)?.length >= IP_BASED_BLOCKING_LIMIT) {
                const expirationTimeIPBlocking = new Date(Date.now() + THIRTY_SECONDS_IN_MS) 
                await addBlockedIp(ip_address, expirationTimeIPBlocking, oneUser.user_id)
            }

            // redis rate blocking documenation before returning
            await incrementRedisKeys(redisClient, redisKeyIp, redisKeyDevice)

            // block ip and/or device if rate limit has been exceeded
            await checkAndBlockIfLimitExceeded(redisClient, redisKeyIp, redisKeyDevice, blockedKeyIp, blockedKeyDevice)

            const remainingAttempts = MAX_FAILED_ATTEMPTS - (failedAttempts.length)
            return res.status(400).json({
                error: "Incorrect email and/or password",
                status: "Login Failure",
                login: false,
                remainingAttempts
            })
        }

        // 6 digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString()
        const hashedOtp = await bcrypt.hash(otp, 10)
        // one time pwd valid for 1 min
        const expirationTimeForOTP = new Date(Date.now() + OTP_EXPIRATION_MS)

        await updateUserMfaOtp(oneUser.user_id, hashedOtp, expirationTimeForOTP)

        // new browser login notification
        const previousLogins = await getLoginHistoryByUserId(oneUser.user_id)
        const isNewDevice = !previousLogins?.some(login =>
            login.ip_address === ip_address &&
            login.device_fingerprint === device_fingerprint
        )

        if (isNewDevice) {
            const mailOptionsNewDevice = createMailOptions(oneUser.email, "New Browser Login Detected",
                `We detected a new browser login to your account.\nIP Address: ${ip_address}\nDevice: ${device_fingerprint}\nIf ` +
                `this wasn't you, please reset your password or contact support.`
            )

            try {
                await transporter.sendMail(mailOptionsNewDevice)
            } catch (error) {
                console.error("Failed to send new browser login email:", error)
            }

        }

        const mailOptions = createMailOptions(oneUser.email, "Your OTP for Login",
            `Your one-time password (OTP) is: ${otp}. It will expire in 1 minutes.`
        )
        // mail for OTP
        try {
            await transporter.sendMail(mailOptions)
            await createLoginAttempt(oneUser.user_id, ip_address, true, device_fingerprint)
            await createLoginHistory(oneUser.user_id, ip_address, device_fingerprint)
            return res.status(200).json({ message: "OTP sent to your email.", user_id: oneUser.user_id })
        } catch (error) {
            console.error("Failed to send OTP email:", error)
            await createLoginAttempt(oneUser.user_id, ip_address, false, device_fingerprint)
            return res.status(500).json({ error: "Failed to send OTP. Please try again." })
        }
    } catch (error) {
        console.error("Error in initial login:", error)
        res.status(500).json({ error: "An error occurred while processing your request. Please try again later." })
    }
})

// sign up, create user route
users.post("/", checkUsernameProvided,
    checkEmailProvided,
    checkPasswordProvided,
    checkUsernameExists,
    checkEmailExists,
    checkEmailFormat,
    checkFirstnameLettersOnly,
    checkLastnameLettersOnly,
    checkUsernameValidity,
    checkDobFormat,
    setDefaultValues,
    checkPasswordStrength("password"), async (req, res) => {
        try {
            const ip_address = req.ip
            const device_fingerprint = req.headers['user-agent'] || "unknown"
            const newUser = req.body
            const salt = await bcrypt.genSalt(10)
            newUser.password = await bcrypt.hash(newUser.password, salt)

            let createdUser = await createUser(newUser)
            if (createdUser.user_id) {
                const token = jwt.sign(
                    {
                        user_id: createdUser.user_id,
                        email: createdUser.email,
                        username: createdUser.username
                    },
                    JWT_SECRET,
                    { expiresIn: '10m' }
                )

                createdUser.password = "***************"
                await createLoginAttempt(createdUser.user_id, ip_address, true, device_fingerprint)
                await createLoginHistory(createdUser.user_id, ip_address, device_fingerprint)
                res.status(201).json({ createdUser, token })
            } else {
                res.status(400).json({
                    error: `error creating user, sql-res:${createdUser.err}`
                })
            }
        } catch (error) {
            res.status(500).json({ error: "error creating user: " + error })
        }
    })

// delete user route
users.delete("/:user_id", verifyToken, checkUserIndex, async (req, res) => {
    try {
        const { user_id } = req.params
        const deletedUser = await deleteUser(user_id)
        if (deletedUser) {
            deletedUser.password = "***************"
            res.status(200).json(deletedUser)
        }
        else {
            res.status(404).json({ error: "user not found => not deleted" })
        }
    }
    catch (error) {
        res.status(400).json({ error: `${error}, error in delete server path` })
    }
})

// password reset route
users.put("/:user_id/password-reset",
    checkUserIndex,
    checkPasswordProvided,
    checkPasswordStrength("password"),
    async (req, res) => {
        try {
            const { user_id } = req.params
            const { password } = req.body

            const user = await getOneUser(user_id)
            if (!user) {
                return res.status(404).json({ error: "User not found" })
            }

            const salt = await bcrypt.genSalt(10)
            const hashedPassword = await bcrypt.hash(password, salt)

            let updatedUser = await updateUserPassword(user_id, hashedPassword)
            if (updatedUser?.user_id) {
                updatedUser.password = "***************"
                res.status(200).json(updatedUser)
            } else {
                res.status(400).json({
                    error: `Error in updating password, try again`
                })
            }
        } catch (error) {
            console.error(`Error in password reset route: ${error}`)
            res.status(500).json({ error: `${error}; Internal server error while resetting password.` })
        }
    })

// update password route
users.put("/:user_id/password",
    verifyToken,
    checkUserIndex,
    checkPasswordProvided,
    checkNewPasswordProvided,
    checkPasswordStrength("newPassword"),
    async (req, res) => {
        try {
            const { user_id } = req.params
            const { password, newPassword } = req.body

            let oneUser = await getOneUser(user_id)
            if (!oneUser) {
                return res.status(404).json({ error: "User not found" })
            }

            const isMatch = await bcrypt.compare(password, oneUser.password)
            if (!isMatch) {
                return res.status(400).json({ error: "Incorrect old password" })
            }

            const salt = await bcrypt.genSalt(10)
            const hashedPassword = await bcrypt.hash(newPassword, salt)

            let updatedUser = await updateUserPassword(user_id, hashedPassword)
            if (updatedUser.user_id) {
                updatedUser.password = "***************"
                res.status(200).json(updatedUser)
            } else {
                res.status(400).json({
                    error: `Error in updating password, try again`
                })
            }
        } catch (error) {
            res.status(400).json({ error: `${error}, error in password update route, in controller` })
        }
    })

// update user route
users.put("/:user_id",
    verifyToken,
    checkUserIndex,
    checkUsernameExistsOtherThanSelf,
    checkEmailExistsOtherThanSelf,
    checkEmailFormat,
    checkFirstnameLettersOnly,
    checkLastnameLettersOnly,
    checkUsernameValidity,
    checkDobFormat,
    setDefaultValues,
    async (req, res) => {
        try {
            const { user_id } = req.params
            const userToUpdate = req.body
            let updatedUser = await updateUser(user_id, userToUpdate)
            if (updatedUser.user_id) {
                updatedUser.password = "***************"
                res.status(200).json(updatedUser)
            }
            else {
                res.status(400).json({
                    error: `error in updating, try again`
                })
            }
        }
        catch (error) {
            res.status(400).json({ error: `${error}, error in user edit route, in controller` })
        }
    })

module.exports = users