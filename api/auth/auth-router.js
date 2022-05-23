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
router.post('/login', checkUsernameExists, (req, res, next) => {
    let { username, password } = req.body;
    if (bcrypt.compareSync(password, req.user.password)) {
      req.session.user = req.user
      res.json({ message: `Welcome ${username}!`})
    } else {
      next({ status: 401, message: "Invalid credentials" })
    }
  })

    // let { username, password } = req.body;

    // let alreadyExists = await Users.findBy({ username }).first() != null;
    // if(alreadyExists) {
    //     next({ status: 400, message: "user already exists" });
    //     return;
    // }

    // let hash = bcrypt.hashSync(password, 10);
    // let result = await Users.add({ username, password: hash });

    // res.status(201).json({ message: `You are now registered as "${username}"`});

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
  router.get('/logout', (req, res, next) => {
    if(req.session.user != null) {
      req.session.destroy();
      res.status(200).json({ message: "logged out" });
    } else {
        res.status(400).json({ message: "no session" });
    }
});

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