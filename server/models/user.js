const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

require('dotenv').config();

const SALT_I = 10;

const userSchema = mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    unique: 1
  },
  password: {
    type: String,
    required: true,
    minlength: 5
  },
  name: {
    type: String,
    required: true,
    maxlength: 100
  },
  lastname: {
    type: String,
    required: true,
    maxlength: 100
  },
  cart: {
    type: Array,
    default: []
  },
  history: {
    type: Array,
    default: []
  },
  role: {
    type: Number,
    default: 0
  },
  token: { type: String }
});

userSchema.pre('save', function(next) {

  if (this.isModified('password')) {
    bcrypt.genSalt(SALT_I, (err, salt) => {
      if (err) return next(err);
  
      bcrypt.hash(this.password, salt, (err, hash) => {
        if (err) return next(err);
  
        this.password = hash;
        next();
      });
    })
  } else {
    next();
  }

})

userSchema.methods.comparePassword = function(payload, cb) {
  bcrypt.compare(payload, this.password, function(err, isMatch){
    if (err) return cb(err);

    cb(null, isMatch);
  });
};

userSchema.methods.generateToken = function(cb) {
  let token = jwt.sign(this._id.toHexString(), process.env.SECRET);

  this.token = token;
  this.save(function(err, value) {
    if (err) return cb(err);

    cb(null, value);
  });
};

userSchema.statics.findByToken = function(token, cb) {
  let user = this;

  jwt.verify(token, process.env.SECRET, function(err, decode) {
    
    user.findOne({ _id: decode, token: token }, function(err, user) {
      if (err) return cb(err);

      cb(null, user);
    });

  })
};

const User = mongoose.model('User', userSchema);

module.exports = { User }