
function calculateRemainingTime(remainingTime) {
    const remainingMinutes = Math.floor(remainingTime / (60 * 1000))
    const remainingSeconds = Math.ceil((remainingTime % (60 * 1000)) / 1000)
    return { remainingMinutes, remainingSeconds }
}

module.exports = calculateRemainingTime
