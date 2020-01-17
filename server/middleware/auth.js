const { User } = require('../models/user');

let auth = (req, res, next) => {
  let token = req.cookies.w_auth;

  User.findByToken(token, (err, value) => {
    if (err) throw err;

    if (!value) return res.json({
      isAuth: false,
      error: true      
    });

    req.token = token;
    req.user = value;
    next();
  });
}

module.exports = { auth };
