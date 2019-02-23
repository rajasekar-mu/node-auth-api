var express = require('express');
var router = express.Router();
var apimodel = require('../model/apimodel');
const { check, validationResult } = require('express-validator/check');
var ObjectId = require('mongodb').ObjectID;
const bcrypt = require('bcrypt');
const saltRounds = 10;

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

//Create user params - name,email, password
router.post('/create', [check('name').isLength({min:3,max:30}).withMessage('name min 3 chars max 30 chars'),check('email').isEmail().withMessage('Please enter valid email'),check('password').isLength({min:5,max:30}).withMessage('Password min 5 chars max 30 chars')], (req, res) => {
	  // Finds the validation errors in this request and wraps them in an object with handy functions
	  const errors = validationResult(req);
	  if (!errors.isEmpty()) {
	    return res.status(422).json({ errors: errors.array() });
	  }
	  apimodel.InsertUser(req.db,{name: req.body.name,email: req.body.email,password: req.body.password,created_date:new Date()}, (result) => {
	  	//console.log(result,'------>');
	  	return res.json(result);
	  });
});

//Login api params  - email,password
router.post('/login', [check('email').isEmail().withMessage('Please enter valid email'),check('password').isLength({min:5}).withMessage('Password min 5 chars max 30 chars')], (req, res) => {
    const errors = validationResult(req);
	  if (!errors.isEmpty()) {
	    return res.status(422).json({ errors: errors.array() });
	  }
	  apimodel.getUserByEmail(req.db,req.body.email, (result) => {
	  	if(result){
	  		if(bcrypt.compareSync(req.body.password,result.password)){
	  			delete result.password;
	  			response = {'status':200,'details':result}
	  		}else{
	  			response = {'status':400,'message':'Password not match'}
	  		}
	  	}else{
	  		response = {'status':400,'message':'user not found'}
	  	}
	  	return res.json(response);
	  });
});

//Forgot password api params - email
router.post('/forgot-password', [check('email').isEmail().withMessage('Please enter valid email')], (req, res) => {
	  // Finds the validation errors in this request and wraps them in an object with handy functions
	  const errors = validationResult(req);
	  if (!errors.isEmpty()) {
	    return res.status(422).json({ errors: errors.array() });
	  }
	  var verify_code = getRandomInt();
	  apimodel.ForgotPassword(req.db,req.body.email,verify_code, (result) => {
      console.log(result,'result');
	  	return res.json(result);
	  });
});

//Reset password api params - email,password,verify_code
router.post('/reset-password', [check('email').isEmail().withMessage('Please enter valid email'),check('password').isLength({min:5}),check('verify_code').isLength({min:5})], (req, res) => {
	  const errors = validationResult(req);
	  if (!errors.isEmpty()) {
	    return res.status(422).json({ errors: errors.array() });
	  }
	  apimodel.ResetPassword(req.db,{email:req.body.email,verify_code:req.body.verify_code,password:req.body.password}, (result) => {
	  	return res.json(result);
	  });
});

//View user detail params - /id
router.get('/view/:id', [check('id').isLength({ min: 5 })], (req, res) => {
	  const errors = validationResult(req);
	  if (!errors.isEmpty()) {
	    return res.status(422).json({ errors: errors.array() });
	  }
	  apimodel.getUser(req.db,req.params.id, (result) => {
	  	return res.json(result);
	  });
});

var getRandomInt = (min=10000, max=99999) => {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min)) + min; //The maximum is exclusive and the minimum is inclusive
}


module.exports = router;
