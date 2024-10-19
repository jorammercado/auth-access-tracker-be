const setDefaultValues = (req, res, next) => {
    req.body.profile_img = req.body.profile_img || "profile image"
    req.body.firstname = req.body.firstname || "unknown first name"
    req.body.lastname = req.body.lastname || "unknown last name"
    req.body.about = req.body.about || "about me"
    req.body.dob = req.body.dob || "00/00/0000"
    return next()
}

//  verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]

    if (!token) {
        return res.status(403).json({ message: 'No token provided' })
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Failed to authenticate token' })
        }
        req.user = decoded

        if (req.params.user_id && req.user.user_id !== Number(req.params.user_id)) {
            return res.status(403).json({ error: 'Unauthorized action' })
        }

        next()
    })
}

module.exports = {
    verifyToken,
    setDefaultValues
}