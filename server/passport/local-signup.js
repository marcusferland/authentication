/**
 * TODO: queue new registration email to be delivered to client
 */

const jwt = require('jsonwebtoken')
const User = require('mongoose').model('User')
const PassportLocalStrategy = require('passport-local').Strategy
const config = require('../../config')

/**
 * Generates a list of backup numbers for totp, in case user doesn't have
 * access to device
 *
 * @return {array}
 */
function calcBackupTotpNumbers() {
  const list = []
	for (let num = 0; num < 16; num++) {
  	list.push( Math.random().toString(36).replace(/[^a-z0-9]+/g, '').substr(1, 5) + '-' +
               Math.random().toString(36).replace(/[^a-z0-9]+/g, '').substr(1, 5) )
  }
  return list
}

/**
 * Return the Passport Local Strategy object.
 */
module.exports = new PassportLocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  session: false,
  passReqToCallback: true
}, (req, email, password, done) => {
  const userData = {
    email: email.trim(),
    password: password.trim(),
    name: req.body.name.trim(),
    role: req.body.role.trim(),
    secret: req.body.secret.trim(),
    backup_totp: calcBackupTotpNumbers()
  }

  const newUser = new User(userData)
  newUser.save((err, user) => {
    if (err) return done(err)
    else return done(null, 200)
  })
})
