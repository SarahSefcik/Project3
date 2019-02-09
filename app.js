// Require express, path, cookieParser, bodyParser
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

// encryption
var bcrypt = require('bcrypt');

// create token
const jwt = require('jsonwebtoken');

// Middleware
const exjwt = require('express-jwt');

const PORT = process.env.PORT || 3002;
var app = express();

// Require model for syncing
var db = require("./models");

// using the header with a content-type of 'Authorization'
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Headers', 'Content-type,Authorization');
  next();
});

// node server setup so requests and responses can be parsed
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// set up an express jsonwebtoken middleware(simply required for express to properly utilize the token for requests) instantiate this with the same secret that will be sent to the client
const jwtMW = exjwt({
  secret: "super secret"
})

// route that the client will pass the entered credentials for verification to. If credentials match, the server sends back a json response with a valid json web token for the client to use for identification
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    db.user.create({
      username: username,
      password: hash
    }).then((result) => {
      console.log("User created: ", result);
      res.json("user created!");
    })
  })
})

app.post('/log-in', (req, res) => {
  const { username, password } = req.body;

  db.user.findOne({
    where: {
      username: username
    }
  }).then((user) => {
    if (user === null) {
      res.status(401).json({
        success: false,
        token: null,
        err: 'Invalid Credentials'
      })
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (result === true) {
        console.log("Valid credentials!");

        let token = jwt.sign(
          {
            username: user.username
          },
          "super secret",
          { expiresIn: 329600 }
        )

        res.json({
          success: true,
          err: null,
          token
        })
      } else {
        console.log("Invalid credentials");
        res.status(401).json({
          success: false,
          token: null,
          err: "Invalid credentials"
        })
      }
    })
  })
})

app.get('/', jwtMW, (req, res) => {
  console.log("WebToken Checked... ");
  res.send("You are authenticated!");
})

db.sequelize.sync().then(() => {
  app.listen(PORT, function () {
    console.log("App listening on PORT " + PORT);
  });
})


module.exports = app;
