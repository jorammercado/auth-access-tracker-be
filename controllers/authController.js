const express = require("express")
const auth = express.Router()
const nodemailer = require("nodemailer")
const bcrypt = require("bcryptjs")

const {
    getOneUserByEmail,
    updateUserResetToken,
    getUserByResetToken
} = require("../queries/users.js")

// forgot password route
auth.post("/forgot-password", async (req, res) => {

    const { email } = req.body

    try {

        const user = await getOneUserByEmail(email)

        if (!user?.email) { // dont inform the user if the email is not found
            return res.status(200).json({ message: "If an account is associated with this email, a reset link will be sent." })
        }

        const resetToken = Math.random().toString(36).substring(2)
        const hashedToken = await bcrypt.hash(resetToken, 10)

        const expirationTime = new Date(Date.now() + 3 * 60 * 1000) // 3 min
        await updateUserResetToken(user.user_id, hashedToken, expirationTime)

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        })

        const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Password Reset Request",
            text: `You requested a password reset. Click on the link to reset your password: ${resetLink}. This link is valid for 3 minutes.`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error)
                return res.status(500).json({ error: "Failed to send email. Please try again.", error })
            } else {
                return res.status(200).json({ message: "If an account is associated with this email, a reset link will be sent." })
            }
        });
    } catch (error) {
        console.error("Error processing forgot password request:", error)
        res.status(500).json({ error: "An error occurred while processing your request. Please try again later." })
    }
})

// verify reset token route
auth.post("/verify-reset-token", async (req, res) => {
    const { token } = req.body;

    try {
        const user = await getUserByResetToken(token);

        if (!user) {
            return res.status(400).json({ error: "Invalid or expired token" });
        }

        return res.status(200).json({ message: "Valid token", user_id: user.user_id });
    } catch (error) {
        console.error("Error verifying reset token:", error)
        res.status(500).json({ error: "An error occurred while verifying the token. Please try again later.", error })
    }
})

// for MFA - verify one time pwd route
auth.post("/verify-otp", async (req, res) => {
    const { user_id, otp } = req.body

    try {
        const oneUser = await getOneUser(user_id)
        if (!oneUser?.user_id) {
            return res.status(404).json({ error: "User not found" })
        }

        const isMatch = await bcrypt.compare(otp, oneUser.mfa_otp);
        if (!isMatch || new Date() > oneUser.mfa_otp_expiration) {
            return res.status(400).json({ error: "Invalid or expired OTP" })
        }

        const token = jwt.sign(
            {
                user_id: oneUser.user_id,
                email: oneUser.email,
                username: oneUser.username
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        )

        oneUser.password = "***************"
        res.status(200).json({ status: "Login Success", login: true, token, oneUser })
    } catch (error) {
        console.error("Error verifying OTP:", error)
        res.status(500).json({ error: "Server error, please try again later" })
    }
})


module.exports = auth
