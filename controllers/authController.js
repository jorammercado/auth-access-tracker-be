const express = require("express")
const auth = express.Router()
const nodemailer = require("nodemailer") 
const bcrypt = require("bcryptjs")

const {
    getOneUserByEmail,
    updateUserResetToken
} = require("../queries/users.js")

// forgot password route
auth.post("/forgot-password", async (req, res) => {
    
    const { email } = req.body
    
    try {
        
        const user = await getOneUserByEmail(email)
        
        if (!user.email) { // dont inform the user if the email is not found
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
                return res.status(500).json({ error: "Failed to send email. Please try again." , error })
            } else {
                return res.status(200).json({ message: "If an account is associated with this email, a reset link will be sent." })
            }
        });
    } catch (error) {
        console.error("Error processing forgot password request:", error)
        res.status(500).json({ error: "An error occurred while processing your request. Please try again later." })
    }
})

module.exports = auth
