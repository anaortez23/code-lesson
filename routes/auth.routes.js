// routes/auth.routes.js
const mongoose = require('mongoose');
const User = require('../models/User.model');

const { Router } = require('express');
const router = new Router();

const bcryptjs = require('bcryptjs');
const saltRounds = 10;

// .get() route ==> to display the signup form to users
router.get('/signup', (req, res) => res.render('auth/signup'));

// .post() route ==> to process form data
router.post('/signup', (req, res, next) => {
  console.log('The form data: ', req.body);
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
    return;
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res
      .status(500)
      .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      // console.log(`Password hash: ${hashedPassword}`);
      return User.create({
        // username: username
        username,
        email,
        // passwordHash => this is the key from the User model
        //     ^
        //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
        passwordHash: hashedPassword
      
    });
    }) 
    .then(userFromDB => {
      console.log('Newly created user is: ', userFromDB);
      res.redirect('/userProfile');
    })
    .catch(error => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { errorMessage: error.message });
      } else if (error.code === 11000) {
        res.status(500).render('auth/signup', {
          errorMessage: 'Username and email need to be unique. Either username or email is already used.'
        });
      } else {
        next(error);
      }  
  });
});

router.get('/userProfile', (req, res) => res.render('users/user-profile'));

/////////////////////////////////////////////////////////////////////////////
///////////////////////////////LOGIN/////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////


router.get('/auth/login', (req, res, next) => {
  res.render('auth/login.hbs');
});

router.post('/login', (req, res, next) => {
  const { email, userPassword } = req.body;

  User.findOne({ email })
  .then((responseFromDB) => {

    if(!responseFromDB){
      res.render('auth/login.hbs', {errorMessage: "Email is not registered. Try different email please"});
    } else if (bcryptjs.compare(userPassword, responseFromDB.passwordHash)){
      // console.log('logged in user is: ', responseFromDB);
      req.session.currentUser = responseFromDB;
      // res.render("users/profile.hbs", {user: responseFromDB});
      res.redirect('/profile');
    } else {
    res.render('auth/login.hbs', {errorMessage: 'Incorrect password.'});
    }
    })
  .catch(err => console.log(`Error while user login ${err}`));
});

router.get('/profile', (req, res, next){
  res.render("user/user-profile.hbs", {userInSession: req.session.currentUser});
})
module.exports = router;