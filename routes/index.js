const express = require('express')
const router = express.Router()
const passport = require('passport')
const jwt = require('jsonwebtoken')
const db = require('../db')
const config = require('../config/settings')
const ObjectID = require('mongodb').ObjectID
const GoogleAuthenticator = require('passport-2fa-totp').GoogeAuthenticator

const authenticated = function (req, res, next) {
  if (req.isAuthenticated()) return next()
  return res.redirect('/login')
}

router.get('/login', function(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
})

router.post('/login', function(req, res, next) {
  passport.authenticate('login', function (err, user, info) {
    if (err) return next(err)
    if ( ! user) return res.status(200).send('No user account').end()

    req.logIn(user, function(err) {
      if (err) {
        return next(err)
      }
      else {
        const payload = {
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            role: user.role,
            secret: user.secret,
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
        return res.status(200).json({
          token: token
        }).end()
      }
    })
  })(req, res, next)
})

router.get('/register', function (req, res, next) {
  //
})

router.post('/register', passport.authenticate('register', {
  successRedirect: '/setup-2fa',
  failureRedirect: '/register',
  failureFlash: true
}))

router.get('/setup-2fa', authenticated, function (req, res, next) {
  // var errors = req.flash('setup-2fa-error');
  var qrInfo = GoogleAuthenticator.register(req.user.username);
  req.session.qr = qrInfo.secret;

  return res.render('setup-2fa', {
    // errors: errors,
    qr: qrInfo.qr
  })
})

router.post('/setup-2fa', authenticated, function (req, res, next) {
  if (!req.session.qr) {
    // req.flash('setup-2fa-error', 'The Account cannot be registered. Please try again.')
    return res.redirect('/setup-2fa')
  }

  const users = db.get().collection('users')
  users.findOne(new ObjectID(req.user._id), function (err, user) {
    if (err) {
      // req.flash('setup-2fa-error', err)
      return res.redirect('/setup-2fa')
    }

    if (!user) {
        // User is not found. It might be removed directly from the database.
      req.logout()
      return res.redirect('/')
    }

    users.update(user, { $set: { secret: req.session.qr } }, function (err) {
      if (err) {
        // req.flash('setup-2fa-error', err);
        return res.redirect('/setup-2fa')
      }

      res.redirect('/profile')
    })
  })
})

router.get('/profile', authenticated, function (req, res, next) {
  return res.render('profile', {
    user: req.user
  })
})

router.get('/logout', authenticated, function (req, res, next) {
  // REMOVE TOKEN
})

module.exports = router
