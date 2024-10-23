const { getAllUsers,
    getOneUserByUserName,
    getOneUserByEmail } = require("../queries/users")

const checkUsernameProvided = (req, res, next) => {
    if (req.body?.username) {
        return next()
    } else {
        res.status(400).json({ error: "username is required!" })
    }
}

const checkUsernameExists = async (req, res, next) => {
    const registeredUserByUserName = await getOneUserByUserName(req.body?.username)
    if (registeredUserByUserName) {
        res.status(400).json({ error: "user already registered with this username" })
    } else {
        next()
    }
}

const checkUsernameExistsOtherThanSelf = async (req, res, next) => {
    const { user_id } = req.params
    const registeredUserByUserName = await getOneUserByUserName(req.body?.username)
    if (registeredUserByUserName?.user_id === Number(user_id) || !registeredUserByUserName)
        return next()
    else
        res.status(400).json({ error: "user already registered with this username" })
}

const checkEmailProvided = (req, res, next) => {
    if (req.body?.email) {
        return next()
    } else {
        res.status(400).json({ error: "email is required!" })
    }
}

const checkEmailExists = async (req, res, next) => {
    const registeredUserByEmail = await getOneUserByEmail(req.body?.email)
    if (registeredUserByEmail?.email) {
        res.status(400).json({ error: "user already registered with this address" })
    } else {
        next()
    }
}

const checkEmailExistsOtherThanSelf = async (req, res, next) => {
    const { user_id } = req.params
    const registeredUserByEmail = await getOneUserByEmail(req.body?.email)
    if (registeredUserByEmail?.user_id === Number(user_id) || !registeredUserByEmail)
        next()
    else
        res.status(400).json({ error: "user already registered with this email" })
}

const checkPasswordProvided = (req, res, next) => {
    if (req.body?.password) {
        return next()
    } else {
        res.status(400).json({ error: "password is required!" })
    }
}

const checkNewPasswordProvided = (req, res, next) => {
    if (req.body?.newPassword) {
        return next()
    } else {
        res.status(400).json({ error: "new password is required!" })
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

const checkEmailFormat = (req, res, next) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    if (emailRegex.test(req.body?.email)) {
        return next()
    } else {
        res.status(400).json({ error: "Invalid email format!" })
    }
}

const checkFirstnameLettersOnly = (req, res, next) => {
    const nameRegex = /^[a-zA-Z]+$/
    if (!req.body?.firstname || nameRegex.test(req.body?.firstname)) {
        return next()
    } else {
        res.status(400).json({ error: "Firstname must contain only letters!" })
    }
}

const checkLastnameLettersOnly = (req, res, next) => {
    const nameRegex = /^[a-zA-Z]+$/
    if (!req.body?.lastname || nameRegex.test(req.body?.lastname)) {
        return next()
    } else {
        res.status(400).json({ error: "Lastname must contain only letters!" })
    }
}

const checkUsernameValidity = (req, res, next) => {
    const { username, firstname, lastname, dob, email } = req.body

    if (firstname?.toLowerCase() + lastname?.toLowerCase() === username?.toLowerCase())
        return res.status(400).json({ error: "Username cannot be the same as your firstname and lastname combined!" })

    if (dob && username === dob)
        return res.status(400).json({ error: "Username cannot be your date of birth!" })

    if (email && username?.toLowerCase() === email?.toLowerCase())
        return res.status(400).json({ error: "Username cannot be your email!" })

    const reservedUsernames = ['admin', 'root', 'superuser', 'administrator', 'support',
        'help', 'moderator', 'system', 'guest', 'owner', 'master', 'test', 'user', 'manager']
    if (reservedUsernames.includes(username?.toLowerCase()))
        return res.status(400).json({ error: "Username cannot be a reserved name!" })

    if (username.length < 3) 
        return res.status(400).json({ error: "Username must be at least 3 characters long!" })
    
    return next()
}

const checkDobFormat = (req, res, next) => {
    const dobRegex = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/
    if (!req.body.dob || dobRegex.test(req.body.dob)) {
        return next()
    } else {
        res.status(400).json({ error: "Date of birth must be in the format ##/##/#### or #/#/####" })
    }
}

const checkPasswordStrength = (passwordField) => (req, res, next) => {
    const password = req.body[passwordField]
    const errors = []

    if (!/(?=.*\d)/.test(password)) 
        errors.push("Password must contain at least one digit.")
    
    if (!/(?=.*[a-z])/.test(password)) 
        errors.push("Password must contain at least one lowercase letter.")
    
    if (!/(?=.*[A-Z])/.test(password)) 
        errors.push("Password must contain at least one uppercase letter.")
    
    if (!/(?=.*[\W_])/.test(password)) 
        errors.push("Password must contain at least one special character.")
    
    if (password.length < 8) 
        errors.push("Password must be at least 8 characters long.")

    if (errors.length > 0) 
        return res.status(400).json({ error: errors.join(" ") })
    
    next()
}


module.exports = {
    checkPasswordStrength,
    checkNewPasswordProvided,
    checkDobFormat,
    checkUsernameValidity,
    checkLastnameLettersOnly,
    checkFirstnameLettersOnly,
    checkEmailFormat,
    checkUsernameProvided,
    checkEmailProvided,
    checkPasswordProvided,
    checkUserIndex,
    checkValidUsername,
    checkUsernameExists,
    checkEmailExists,
    checkUsernameExistsOtherThanSelf,
    checkEmailExistsOtherThanSelf
}
