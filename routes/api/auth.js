const express = require('express');

const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const auth = require('../../middleware/auth');
const User = require('../../models/User');

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async (req, res) => {
  // try to Authorize the user
  try {
    // await the response of the user found by ID, don't return the PW
    const user = await User.findById(req.user.id).select('-password');
    // send a json response of the user
    res.json(user);
  } catch (err) { // otherwise return an error with status 500
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   POST api/auth
// @desc    Authenticate user & get token
// @access  Public
router.post('/', // make a post request to the db
  [ // ensure there is a name, email, and password
    // check for a name, err msg: name required; rule is for name to not be empty
    check('email', 'Please enter a valid email').isEmail(), // ensures formatted as email address
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => { // request and response
    const errors = validationResult(req);
    // if the errors field is not empty (contains errors) in the validation result
    if (!errors.isEmpty()) {
      // return a response of bad request (code 400) and show all the errors
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // See if user exists - search by user
      const user = await User.findOne({ email });

      // if user doesn't exist
      if (!user) {
        // send back a status of 400 (Bad request) with error + msg (and other errs if any)
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid credentials' }] });
      }

      // attempt to match the email and password to an existing user
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid credentials' }] });
      }

      // return jsonwebtoken
      const payload = { // info that we want to send; user ID in our case
        user: {
          id: user.id,
        },
      };
      // jwt sign the token, with payload, our secret, token expiration time, and callback
      // the callback throws an error if there is one, else sends the token response in json format
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 360000 }, // optional but recommended
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        },
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  });

module.exports = router;
