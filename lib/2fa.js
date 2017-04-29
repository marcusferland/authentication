const crypto = require('crypto')
const config = require('../config/settings.js')
const pattern = config.totpBackupCodesPattern

var TFA = module.exports = {}

TFA.generateBackupCodes = (numBackupCodes = 10, cb) => {

  var codes = []
  for (var c = 0; c < numBackupCodes; c++) {
    TFA.generateBackupCode(code => {
      codes.push(code)
      if (codes.length === numBackupCodes) cb(codes)
    })
  }
  return codes
}

TFA.generateBackupCode = cb => {

  // how many crypto bytes do we need?
  const patternLength = Math.ceil((pattern.split('x').length) - 1 / 2)

  crypto.randomBytes(patternLength, (err, buf) => {
    if (err) return err
    const chars = buf.toString('hex')
    let code = ''

    // number of crypto characters that we've used
    var xs = 0;
    for (var i = 0; i < pattern.length; i++) {
      code += pattern[i] === 'x' ? chars[xs++] : pattern[i]
    }
    cb(code)
  })
}
