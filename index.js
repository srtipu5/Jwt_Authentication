require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const bodyParser = require('body-parser')
const axios = require('axios')
const app = express()

app.use(bodyParser.json())

const PORT = process.env.PORT || 3000
const SECRET_KEY = process.env.SECRET_KEY
const ACCESS_TOKEN_EXPIRATION = process.env.ACCESS_TOKEN_EXPIRATION
const REFRESH_TOKEN_EXPIRATION = process.env.REFRESH_TOKEN_EXPIRATION

const users = [
    { id: 1, username: 'user', password: 'password', accessToken: '', refreshToken: ''},
    { id: 2, username: 'tipu', password: 'password', accessToken: '', refreshToken: '' },
  ]
  
  const generateAccessToken = (user) => {
    return jwt.sign(user, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRATION })
  }
  
  const generateRefreshToken = (user) => {
    return jwt.sign(user, SECRET_KEY, { expiresIn: REFRESH_TOKEN_EXPIRATION })
  }

  const authenticateToken = async (req, res, next) => {

    const userIndex = users.findIndex(u => u.id === +req.header('Authorization'))
    if (userIndex === -1) return res.status(403).json({ error: 'Forbidden' })
   
    const token = users[userIndex].accessToken 
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const user = jwt.verify(token, SECRET_KEY)
      req.user = user
      return next()
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        try {
          const response = await axios.post(`http://localhost:${PORT}/token`, {
            refreshToken:  users[userIndex].refreshToken, 
          })
          req.user = jwt.verify(response.data.accessToken, SECRET_KEY)
          return next()
        } catch (error) {
          console.error('Error refreshing token:', error.message)
          return res.status(403).json({ error: 'Forbidden' })
        }
      } else {
        console.error('Error verifying token:', err.message)
        return res.status(403).json({ error: 'Forbidden' })
      }
    }
  }  

  app.post('/token', (req, res) => {
    const refreshToken = req.body.refreshToken
  
    if (!refreshToken) {
      return res.status(403).json({ error: 'Refresh token is required' })
    }
  
    jwt.verify(refreshToken, SECRET_KEY, (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid refresh token' })
      }
  
      const accessToken = generateAccessToken({ id: user.id, username: user.username })
      const newRefreshToken = generateRefreshToken({ id: user.id, username: user.username })
  
      res.json({ accessToken, refreshToken: newRefreshToken })
    })
  })

  app.post('/login', (req, res) => {
    const { username, password } = req.body
    const userIndex = users.findIndex(u => u.username === username && u.password === password)

    if (userIndex !== -1) {
      users[userIndex].accessToken = generateAccessToken({ id: users[userIndex].id, username: username })
      users[userIndex].refreshToken = generateRefreshToken({ id: users[userIndex].id, username: username })
      res.json({ message: `You are logged in !! Your Authorization Code is : ${users[userIndex].id}`})
  
    } else {
      res.status(401).json({ error: 'Invalid credentials' })
    }
  })

  // protected route
  app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route!!', user: req.user })
  })
  
  
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`)
  })