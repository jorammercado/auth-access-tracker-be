
function createMailOptions(to, subject, text) {
    return {
        from: process.env.EMAIL_USER,
        to,
        subject,
        text,
    }
}

module.exports = createMailOptions
