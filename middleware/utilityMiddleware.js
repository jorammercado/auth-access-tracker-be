const setDefaultValues = (req, res, next) => {
    req.body.profile_img = req.body.profile_img || "profile image"
    req.body.firstname = req.body.firstname || "unknown first name"
    req.body.lastname = req.body.lastname || "unknown last name"
    req.body.about = req.body.about || "about me"
    req.body.dob = req.body.dob || "00/00/0000"
    return next()
}

module.exports = {
    setDefaultValues
}