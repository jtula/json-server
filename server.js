// credits to techiediaries (https://www.techiediaries.com/fake-api-jwt-json-server/)

const fs = require("fs")
const bodyParser = require("body-parser")
const jsonServer = require("json-server")
const jwt = require("jsonwebtoken")

const SECRET_KEY = "123456789"
const expiresIn = "8h"

const server = jsonServer.create()
const router = jsonServer.router("db.json")
const userdb = JSON.parse(fs.readFileSync("users.json", "UTF-8"))

server.use(bodyParser.urlencoded({ extended: true }))
server.use(bodyParser.json())
server.use(jsonServer.defaults())

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn })
}

function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err
  )
}

function getProfile(email) {
  return userdb.users.find((res) => res.email === email)
}

function isAuthenticated({ email, password }) {
  return (
    userdb.users.findIndex(
      (user) => user.email === email && user.password === password
    ) !== -1
  )
}

server.post("/auth/login", (req, res) => {
  const { email, password } = req.body
  if (isAuthenticated({ email, password }) === false) {
    const status = 401
    const message = "Incorrect email or password"
    res.status(status).json({ status, message })
    return
  }
  const user = getProfile(email)
  const accessToken = createToken({ email, password })
  res.status(200).json({ accessToken, user })
})

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    const status = 401
    const message = "Bad authorization header"
    res.status(status).json({ status, message })
    return
  }
  try {
    verifyToken(req.headers.authorization.split(" ")[1])
    next()
  } catch (err) {
    const status = 401
    const message = "Error: accessToken is not valid"
    res.status(status).json({ status, message })
  }
})

server.use(bodyParser.urlencoded({ extended: true }))
server.use(bodyParser.json())

server.use(router)

server.listen(8000, () => {
  console.log("Run Auth API Server")
})
