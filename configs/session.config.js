
const session = require("express-session");

module.exports = app => {
  app.use(session({ 
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: false,
  cookie: { secure: true,
    sameSite: 'none',
    httpOnly: true,
    maxAge: 60000
  }

  }));
};