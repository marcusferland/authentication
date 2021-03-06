const cluster = require('cluster')

if (cluster.isMaster) {

  const numCPUs = require('os').cpus().length
  console.log(`Master cluster setting up ${numCPUs} workers...`)

  for (var i = 0; i < numCPUs; i++) cluster.fork()

  cluster.on('online', worker => {
    console.log(`Worker ${worker.process.pid} is online`)
  })

  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died with code: ${code}, and signal: ${signal}`)
    console.log('Starting a new worker')
    cluster.fork()
  })
}
else {

  const app = require('express')()
  const cors = require('cors')
  const bodyParser = require('body-parser')
  const passport = require('passport')
  const config = require('./config')

  // connect to the database and load models
  require('./server/models').connect(config.dbUri)

  app.use(cors())

  // tell the app to parse HTTP body messages
  app.use(bodyParser.urlencoded({ extended: false }))

  // pass the passport middleware
  app.use(passport.initialize())

  // load passport strategies
  const localSignupStrategy = require('./server/passport/local-signup')
  const localLoginStrategy = require('./server/passport/local-login')
  passport.use('local-signup', localSignupStrategy)
  passport.use('local-login', localLoginStrategy)

  // pass the authorization checker middleware
  const authCheckMiddleware = require('./server/middleware/auth-check')
  app.use('/api', authCheckMiddleware)

  // routes
  const authRoutes = require('./server/routes/auth')
  const apiRoutes = require('./server/routes/api')
  app.use('/auth', authRoutes)
  app.use('/api', apiRoutes)

  // start the server
  app.listen(config.serverPort, () => {
    console.log(`Server is running on http://localhost:${config.serverPort} or http://127.0.0.1:${config.serverPort}`)
  })
}
