const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const {
    getOneUserByEmail,
    getOneUserByUserName,
    createUser,
    deleteUser,
    updateUser,
    updateUserPassword,
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

const users = express.Router()
const JWT_SECRET = process.env.JWT_SECRET

// login route
users.post("/login", checkEmailProvided, checkPasswordProvided, async (req, res) => {
    try {
        let oneUser = await getOneUserByEmail(req.body)
        if (!oneUser) {
            return res.status(404).json({ error: `user with ${req.body.email} email not found!` })
        }

        const isMatch = await bcrypt.compare(req.body.password, oneUser.password);
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
            { expiresIn: '1h' }
        );

        oneUser.password = "***************";
        res.status(200).json({ status: "Login Success", login: true, token, oneUser })
    } catch (error) {
        res.status(500).json({ error: error })
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
                    { expiresIn: '5m' }
                )

                createdUser.password = "***************"
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

            let oneUser = await getOneUserByUserName({ user_id })
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