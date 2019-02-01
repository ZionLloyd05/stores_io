const passport = require('passport')
const crypto = require('crypto')
const mongoose = require('mongoose')
const User = mongoose.model('User')
const promisify = require('es6-promisify')

exports.login = passport.authenticate('local', {
    failureRedirect: '/login',
    failureFlash: 'Failed Login',
    successRedirect: '/',
    successFlash: 'You are logged in'
})

exports.logout = (req, res) => {
    req.logout()
    req.flash('success', 'You are logged out')
    res.redirect('/')
}

exports.isLoggedIn = (req, res, next) => {
    if(req.isAuthenticated()){
        return next()
    }
    req.flash('error', 'Oopes, you must be logged in')
    res.redirect('/login')
}

exports.forgot = async (req, res) => {
    // 1. check if user exist
    const user = await User.findOne({ email: req.body.email })
    if(!user) {
        req.flash('error', 'No account exist with the email')
        return res.redirect('/login')
    }
    // 2. set reset tokens and expiry on their acc
    user.resetPasswordToken = crypto.randomBytes(20).toString('hex')
    user.resetPasswordExpires = Date.now() + 3600000 //an hour from now
    await user.save()
    // 3. send token to email
    const resetUrl = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`
    req.flash('success', `You have been emailed a password reset link. ${resetUrl}`)
    res.redirect('/login')
    // http://localhost:3000/account/reset/8d3bd30779e4b384bb9fb42ac81558606788648e
}

exports.reset = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
    })
    if(!user){
        req.flash('error', 'Password reset is invalid or has expired')
        return res.redirect('/login')
    }

    res.render('reset', { title: 'Reset your password' })
}

exports.confirmedPasswords = (req, res, next) => {
    if(req.body.password === req.body['password-confirm']){
        return next()
    }
    req.flash('error', 'Passwords do not match')
    return res.redirect('/login')
}

exports.update = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
    })
    if(!user){
        req.flash('error', 'Password reset is invalid or has expired')
        return res.redirect('/login')
    }

    const setPassword = promisify(user.setPassword, user)
    await setPassword(req.body.password)
    user.resetPasswordToken = undefined
    user.resetPasswordExpires = undefined
    const updatedUser = await user.save()
    await req.login(updatedUser)
    req.flash('success', 'It worked')
    res.redirect('/')
}