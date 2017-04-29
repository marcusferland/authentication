const app = require('express')()
const cors = require('cors')
const bodyParser = require('body-parser')
const passport = require('passport')
const session = require('express-session')
const flash = require('connect-flash')
const setupPassport = require('./config/passport')
const db = require('./db')
const routes = require('./routes')
const twofa = require('./lib/2fa.js')

twofa.generateBackupCodes(10, codes => {
  console.log(codes)
})

app.use(cors())

// tell the app to parse HTTP body messages
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

// pass the passport middleware
setupPassport(passport)
app.use(passport.initialize())

// sessions
app.use(session({
  secret: '0_v7^^JxCcUJLGNeYf6l',
  name: 'SessionID',
  resave: false,
  saveUninitialized: true,
  cookie: {
    // secure: true,        // Use in production. Send session cookie only over HTTPS
    httpOnly: true,
  }
}))

app.use(flash())

// routes
app.use('/', routes)

module.exports = app
