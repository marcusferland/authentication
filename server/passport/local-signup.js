/**
 * TODO: queue new registration email to be delivered to client
 */

const jwt = require('jsonwebtoken');
const User = require('mongoose').model('User');
const PassportLocalStrategy = require('passport-local').Strategy;
const config = require('../../config');

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
    role: req.body.role.trim()
  };

  const newUser = new User(userData);
  newUser.save((err, user) => {
    if (err) return done(err);

    const payload = {
      sub: user._id,
      user: {
        email: user.email,
        name: user.name,
        role: user.role
      }
    };

    // create a token string
    const token = jwt.sign(
      payload,
      config.jwtSecret, {
        expiresIn: config.tokenExpires
      }
    )

    return done(null, token);

    // return done(null);
  });
});
