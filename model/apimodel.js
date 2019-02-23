var ObjectId = require('mongodb').ObjectID;
const bcrypt = require('bcrypt');
const saltRounds = 10;

exports.InsertUser	= (db,data,callback) =>	{
	db.collection("customers").findOne({'email':data.email},{_id:1}, (err,db_res) =>	{
		if(db_res){
			var response = {'status':403,'error':'user exist'};
			callback(response);
		}else{
			var hash = bcrypt.hashSync(data.password, saltRounds);
			data.password = hash;
			db.collection("customers").insertOne(data,(err,res)=>	{
				//console.log(res);
				if(err){
					var response = {'status':403,'error':err};
				}else{
					var response = {'status':200,'message':'Insert sucess','_id':res.insertedId};
				}
				callback(response);
			})
		}
	});
}

exports.getUserByEmail = (db,email,callback) => {
	db.collection("customers").findOne({'email':email},{_id:1,email:1,name:1,password:1}, (err,data) =>{
		callback(data);
	})
}

exports.ForgotPassword = (db,email,code,callback) => {
	db.collection("customers").updateOne({'email':email},{$set:{reset_code:code}}, (err,db_res) =>	{
		//console.log(err,'err----');
		if(db_res.matchedCount){
			var response = {'status':200,'message':'Please verify code and reset password','code':code};
		}else{
			var response = {'status':400,'message':'no user found'};
		}
		callback(response);
	})
}

exports.ResetPassword = (db,data,callback) => {
	db.collection("customers").findOne({'email':data.email,'reset_code':parseInt(data.verify_code)},{_id:1}, (err,db_user) =>{
		if(db_user){
			var hash = bcrypt.hashSync(data.password, saltRounds);
			db.collection("customers").updateOne({'_id':ObjectId(db_user._id)},{$set:{password:hash},$unset:{reset_code:1}}, (err,db_res) =>	{
				if(db_res.matchedCount){
					var response = {'status':200,'message':'Reset successfully'};
				}else{
					var response = {'status':400,'message':'no user found'};
				}
				callback(response);
			})
		}else{
			var response = {'status':400,'message':'no user found'};
			callback(response);
		}
	})
}

exports.getUser = (db,id,callback) => {
	db.collection("customers").findOne({'_id':ObjectId(id)},{_id:1,name:1,email:1}, (err,data) =>	{
		if(data){
			var response = {'status':200,'data':data};
		}else{
			var response = {'status':400,'data':'no user found'};
		}
		callback(response);
	})
}
