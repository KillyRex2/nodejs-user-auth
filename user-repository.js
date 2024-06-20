import DBLocal from 'db-local'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    Validation.username(username)
    Validation.password(password)
    const user = User.findOne({ username })

    if (user) throw new Error('This username is already taken!')
    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS) // hashSync -> Bloquea el tread principal
    // Crear usuario
    const id = crypto.randomUUID()

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()

    return id
  }

  static async login ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error(`User ${username} not found`)

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('password not valid')

    // Forma elegante de quitarle propiedades a un objeto
    const { password: _, ...publicUser } = user

    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('Username must be a string')
    if (username.length < 3) throw new Error('Username must be at least 3 characters long')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('Password must be a string')
    if (password.length < 6) throw new Error('Password must be at least 6 characters long')
  }
}
