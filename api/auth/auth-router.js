// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model');
const router = express.Router()
const { 
  restricted, 
  checkUsernameFree, 
  checkUsernameExists, 
  checkPasswordLength 
} = require('./auth-middleware')

router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  const username = req.body.username
  const password = req.body.password

  let hash = bcrypt.hashSync(password, 10)
  let result = await Users.add({username, password: hash})

  res.status(200).json(result)
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/login', checkUsernameExists, async (req, res) => {
  // const username = req.body.username
  // const password = req.body.password

  // let result = await Users.findBy({ username })

  
  // req.session.user = result
  // res.status(200).json(`Welcome ${username}!`)
  try {
    let { username, password } = req.body;

    let alreadyExists = await Users.findBy({ username }).first() != null;
    if(alreadyExists) {
        next({ status: 400, message: "user already exists" });
        return;
    }

    let hash = bcrypt.hashSync(password, 10);
    let result = await Users.add({ username, password: hash });

    res.status(201).json({ message: `You are now registered as "${username}"`});
} catch(err) {
    next(err);
}
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router