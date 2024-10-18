const { getAllUsers,
    getOneUserByUserName,
    getOneUserByEmail } = require("../queries/users")

const checkUsername = (req, res, next) => {
    if (req.body.username) {
        return next()
    } else {
        res.status(400).json({ error: "username is required!" })
    }
}

const checkUsernameExists = async (req, res, next) => {
    const registeredUserByUserName = await getOneUserByUserName(req.body)
    if (registeredUserByUserName) {
        res.status(400).json({ error: "user already registered with this username" })
    } else {
        next()
    }
}

const checkUsernameExistsOtherThanSelf = async (req, res, next) => {
    const { user_id } = req.params
    const registeredUserByUserName = await getOneUserByUserName(req.body)
    if (registeredUserByUserName?.user_id === Number(user_id) || !registeredUserByUserName)
        return next()
    else
        res.status(400).json({ error: "user already registered with this username" })
}

const checkEmail = (req, res, next) => {
    if (req.body.email) {
        return next()
    } else {
        res.status(400).json({ error: "email is required!" })
    }
}

const checkEmailExists = async (req, res, next) => {
    const registeredUserByEmail = await getOneUserByEmail(req.body)
    if (registeredUserByEmail) {
        res.status(400).json({ error: "user already registered with this address" })
    } else {
        next()
    }
}

const checkEmailExistsOtherThanSelf = async (req, res, next) => {
    const { user_id } = req.params
    const registeredUserByEmail = await getOneUserByEmail(req.body)
    if (registeredUserByEmail?.user_id === Number(user_id) || !registeredUserByEmail)
        next()
    else
        res.status(400).json({ error: "user already registered with this username" })
}

const checkPassword = (req, res, next) => {
    if (req.body.password) {
        return next()
    } else {
        res.status(400).json({ error: "password is required!" })
    }
}

const checkValidUsername = async (req, res, next) => {
    const allUsers = await getAllUsers()
    const { username } = req.params
    const allUsernames = allUsers.map(e => e.username)
    if (allUsernames.includes(Number(username)))
        return next()
    else
        res.status(400).json({
            error: `server error - invalid username sent`
        })
}

const checkUserIndex = async (req, res, next) => {
    const allUsers = await getAllUsers()
    const { user_id } = req.params
    const ids = allUsers.map(e => e.user_id)
    if (ids.includes(Number(user_id)))
        return next()
    else
        res.status(400).json({
            error: `server error - invalid user_id sent`
        })
}



module.exports = {
    checkUsername,
    checkEmail,
    checkPassword,
    checkUserIndex,
    checkValidUsername,
    checkUsernameExists,
    checkEmailExists,
    checkUsernameExistsOtherThanSelf,
    checkEmailExistsOtherThanSelf
}
