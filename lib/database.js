var env = require('node-env-file');
env(__dirname.substring(0, __dirname.lastIndexOf('\\')) + '/.env');
const mysql = require('mysql');
var connection = mysql.createConnection({
    host     : process.env.HOST,
    user     : process.env.USER,
    password : process.env.PASSWORD,
    database : process.env.DATABASE
});

connection.connect(function(err){
    if(!err) {
        console.log("Database is connected ... nn");    
    } else {
        console.log("Error connecting database ... nn" + err);    
    }
});

connection.query(
  'CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, status VARCHAR(255), username VARCHAR(255) NOT NULL,' + 
  'password VARCHAR(255) NOT NULL, api_token VARCHAR(255) NOT NULL, client_id TEXT, profile_pic TEXT NOT NULL, favs TEXT,' + 
  'location TEXT, create_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, public_key TEXT)');
connection.end();