const db = require('../db')
const ObjectID = require('mongodb').ObjectID
const bcrypt = require('bcrypt')
const GoogleAuthenticator = require('passport-2fa-totp').GoogeAuthenticator
const TwoFAStrategy = require('passport-2fa-totp').Strategy
const config = require('./settings')

module.exports = function (passport) {
  const INVALID_LOGIN = 'Invalid username, password, and/or TOTP code'

  passport.serializeUser(function (user, done) {
    return done(null, user._id)
  })

  passport.deserializeUser(function (id, done) {
    const users = db.get().collection('users')
    users.findOne(new ObjectID(id), function (err, user) {
      if (err) return done(err)
      else if (user === null) return done(null, false)
      else return done(null, user)
    })
  })

  passport.use('login', new TwoFAStrategy({
    usernameField: 'email',
    passwordField: 'password',
    codeField: 'code'
  }, function (username, password, done) {

    process.nextTick(function () {
      const users = db.get().collection('users')
      users.findOne({ email: username }, function (err, user) {
        if (err) return done(err)

        if (user === null) return done(null, false, { message: INVALID_LOGIN })

        bcrypt.compare(password, user.password, function (err, result) {
          if (err) return done(err)

          if (result === true) return done(null, user)
          else return done(null, false, { message: INVALID_LOGIN })
        })
      })
    })
  }, function (user, done) {
    // 2nd step verification: TOTP code from Google Authenticator

    if ( ! user.secret) {
      done(new Error('Google Authenticator is not setup yet'))
    }
    else {
      // Google Authenticator uses 30 seconds key period
      // https://github.com/google/google-authenticator/wiki/Key-Uri-Format

      const secret = GoogleAuthenticator.decodeSecret(user.secret)
      return done(null, secret)
    }
  }))

  passport.use('register', new TwoFAStrategy({
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: true,
      skipTotpVerification: true
  }, function (req, username, password, done) {
    // 1st step verification: validate input and create new user

    if (!/^[A-Za-z0-9_]+$/g.test(req.body.username)) {
      return done(null, false, { message: 'Invalid username' })
    }

    if (req.body.password.length === 0) {
      return done(null, false, { message: 'Password is required' })
    }

    if (req.body.password !== req.body.confirmPassword) {
      return done(null, false, { message: 'Passwords do not match' })
    }

    const users = db.get().collection('users')
    users.findOne({ username: username}, function (err, user) {
      if (err) return done(err)

      if (user !== null) {
        return done(null, false, { message: 'Invalid username' });
      }

      bcrypt.hash(password, null, null, function (err, hash) {
        if (err) return done(err)

        var user = {
          username: username,
          password: hash
        }

        users.insert(user, function (err) {
          if (err) return done(err)
          return done(null, user)
        })
      })
    })
  }))
}