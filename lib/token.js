const crypto = require('crypto')

module.exports = {
  generateRandomToken: function(callback) {
    crypto.randomBytes(256, (ex, buffer) => {
      if (ex) return callback(error('server_error'))

      const token = crypto
        .createHash('sha1')
        .update(buffer)
        .digest('hex');

      callback(false, token)
    })
  }
}
