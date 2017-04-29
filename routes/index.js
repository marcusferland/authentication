const express = require('express')
const router = express.Router()
const passport = require('passport')
const jwt = require('jsonwebtoken')
const db = require('../db')
const token = require('../lib/token')
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
    if ( ! user) return res.status(200).json({
      err: err,
      message: info
    }).end()

    req.logIn(user, function(err) {
      if (err) return next(err)

      const payload = {
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          role: user.role,
          secret: user.secret
        }
      }

      // create a token string
      const accessToken = jwt.sign(
        payload,
        config.jwtSecret, {
          expiresIn: config.tokenExpires
        }
      )

      token.generateRandomToken(function(err, refreshToken) {
        const refreshTokensCollection = db.get().collection('refreshTokens')

        refreshTokensCollection.save({
          "userId": ObjectID(user._id),
          "token": refreshToken,
          "expires": 86400
        })

        return res.status(200).json({
          err: err,
          success: true,
          token: accessToken,
          refreshToken: refreshToken
        }).end()
      })
    })
  })(req, res, next)
})

router.post('/token', function(req, res, next) {
  if ( ! req.body.grant_type) return res.json({
    err: 'Please specify a grant_type in your request.'
  }).end()

  if ( ! req.body.token) return res.json({
    err: 'Please send a refresh token with your request.'
  }).end()

  switch (req.body.grant_type) {
    case 'refresh_token':
      const refreshTokens = db.get().collection('refreshTokens')
      refreshTokens.findOne({ token: req.body.token }, function (err, token) {
        if (err) return done(err)

        if (token === null) return done(null, false, { message: INVALID_LOGIN })

        if (token.userId) {
          const users = db.get().collection('users')
          users.findOne({ _id: ObjectID(token.userId) }, function (err, user) {
            if (err) return done(err)

            if (user === null) return done(null, false, { message: INVALID_LOGIN })

            const payload = {
              user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                secret: user.secret
              }
            }

            // create a token string
            const access_token = jwt.sign(
              payload,
              config.jwtSecret, {
                expiresIn: config.tokenExpires
              }
            )

            return res.json({
              access_token: access_token
            }).end()
          })
        }
      })
      break;
    default: return res.json({
      err: 'Please specify a grant_type in your request.'
    }).end()
  }
})

router.get('/register', function(req, res, next) {
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
