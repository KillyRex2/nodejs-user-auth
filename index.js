import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')
// middleware que checa si el body tiene un json a req.body
app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }
  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch (err) {}

  next() // -> seguir a la sig ruta o middleware
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', user)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_JWT_KEY,
      {
        expiresIn: '1h'
      })

    // const Refreshtoken = jwt.sign(
    //   { id: user._id, username: user.username },
    //   SECRET_JWT_KEY,
    //   {
    //     expiresIn: '7d'
    //   })

    res
      .cookie('access_token', token, {
        httpOnly: true, // Cookie solo accesible desde el server
        secure: process.env.SECRET_JWT_SEC === 'production', // la cookie solo se puede acceder en https
        sameSite: 'strict', // la cookie solo accesible en el mismo dominio
        maxAge: 1000 * 60 * 60 // la cookie tiene un tiempo de validez de 1 hora 
      })
      .send({ user, token })
  } catch (err) {
    res.status(401).send(err.message)
  }
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body

  // Verifica que los datos fueron recibidos
  console.log('Register request body:', req.body)

  console.log({ username, password })

  if (!username || !password) {
    return res.status(400).send({ error: 'Username and password are required' })
  }

  try {
    const id = await UserRepository.create({ username, password })
    res.send({ id })
  } catch (err) {
    console.error(err) // Para que puedas ver el error exacto en la consola
    res.status(400).send({ error: err.message })
  }
})

app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .json({ message: 'logout successful' })
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Access denied')
  res.render('protected', user)
})

app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`)
})
