const jwt = require('jsonwebtoken')
const ObjectID = require('mongodb').ObjectID
const GoogleAuthenticator = require('passport-2fa-totp').GoogeAuthenticator
const TwoFAStartegy = require('passport-2fa-totp').Strategy
const config = require('../../config')

/**
 * Return the Passport Local Strategy object.
 */
module.exports = new TwoFAStartegy({
  usernameField: 'email',
  passwordField: 'password',
  codeField: 'code',
  session: false,
  passReqToCallback: true
}, (req, email, password, done) => {

  process.nextTick(function () {
    const userData = {
      email: email.trim(),
      password: password.trim()
    }

    // find a user by email address
    const Users = db.get().collection('users')
    return Users.findOne({ email: userData.email }, (err, user) => {
      if (err) return done(err)

      if (!user) {
        const error = new Error('Incorrect email or password')
        error.name = 'IncorrectCredentialsError'

        return done(error)
      }

      // check if a hashed user's password is equal to a value saved in the database
      return user.comparePassword(userData.password, (passwordErr, isMatch) => {
        if (err) return done(err)

        if (!isMatch) {
          const error = new Error('Incorrect email or password')
          error.name = 'IncorrectCredentialsError'

          return done(error)
        }

        // 2nd step verification: TOTP code from Google Authenticator
        if ( ! user.secret) {
            done(new Error('Google Authenticator is not setup yet.'))
        }
        else {

          // Google Authenticator uses 30 seconds key period
          // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
          const secret = GoogleAuthenticator.decodeSecret(user.secret)

          const payload = {
            user: {
              id: user._id,
              email: user.email,
              name: user.name,
              role: user.role,
              secret: secret,
              backup_totp: user.backup_totp
            }
          }

          // create a token string
          const token = jwt.sign(
            payload,
            config.jwtSecret, {
              expiresIn: config.tokenExpires
            }
          )

          done(null, token, 30)
        }

      })
    })
  })
})
