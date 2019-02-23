var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var config = require('config');
var dbConfig = config.get('dbConfig');
var expressMongoDb = require('express-mongo-db');

var indexRouter = require('./routes/index');
var apiRouter = require('./routes/api');

//If you needed authentication means to set Authneed - 1 & set correct user name & pwd
if(dbConfig.Authneed==1){
	var db_url = `mongodb://${dbConfig.userName}:${dbConfig.password}@${dbConfig.host}:${dbConfig.port}/${dbConfig.dbName}`;
}else{
	var db_url = `mongodb://${dbConfig.host}:${dbConfig.port}/${dbConfig.dbName}`;
}
//console.log(db_url);
var app = express();
//DB coonection establish
app.use(expressMongoDb(db_url));
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/api', apiRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
