const express = require('express');

const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator/check');

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post('/', // make a post request to the db
  [ // ensure there is a name, email, and password
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'Please enter a password with 10 or more characters').isLength({ min: 10 }),
  ],
  async (req, res) => { // request and response
    const errors = validationResult(req);
    // if the errors field is not empty (contains errors) in the validation result
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      // See if user exists - search by user
      let user = await User.findOne({ email });

      // if user exists
      if (user) {
        // send back a status of 400 (Bad request) with error + msg (and other errs if any)
        return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
      }

      // Get user's gravitar
      const avatar = gravatar.url(email, {
        s: '200', // default size
        r: 'pg', // 'movie' rating
        d: 'mm', // default avatar if one is not specified/exists
      });

      // create instance of the user with validated info from above
      user = new User({
        name, email, avatar, password,
      });

      // encrypt password
      const salt = await bcrypt.genSalt(10); // salt the pw with 10 'rounds'
      // assign the password to the hashed password
      user.password = await bcrypt.hash(password, salt);

      await user.save(); // save the user

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
