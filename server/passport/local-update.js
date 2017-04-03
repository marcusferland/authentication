const jwt = require('jsonwebtoken')
const User = require('mongoose').model('User')
const config = require('../../config')

module.exports = (req, res, next) => {
  const userid = req.body.userid
  let totps = req.body.totps

  if (totps.constructor === String) totps = totps.split(',')

  User.findByIdAndUpdate(userid, {
    backup_totp: totps
  }, (err, user) => {
    if (err) return res.status(500).json({
      error: err
    }).end()
    else return res.status(200).json({
      user: user
    }).end()
  })
}
