require('dotenv').config()
var app = require('express')();
var crypto = require('crypto');
var request = require('request');
var base64 = require('base-64');
var bcrypt = require('bcryptjs');
var busboy = require('connect-busboy'); 
var fs = require('fs-extra');
var bodyParser = require('body-parser');
var http = require('http').Server(app);
var io = require('socket.io')(http);
var NodeRSA = require('node-rsa');
var key = new NodeRSA({b: 1024});
key.setOptions({encryptionScheme: 'pkcs1'});
var gPrivateKey = key.exportKey("pkcs8-private");
var gPublicKey = key.exportKey("pkcs8-public-pem");
var users_online = {}
var API_KEY = process.env.API_KEY || 'none';
var mysql = require('mysql');
var pool  = mysql.createPool({
  host     : process.env.HOST,
  user     : process.env.USER,
  password : process.env.PASSWORD,
  database : process.env.DATABASE
});

io.on('connection', function(socket){
    
    socket.on('status', function(username){
        socket.username = username;
        users_online[username] = socket.id;
        console.log('a user connected  ' + socket.username);
    });
    
    socket.on('disconnect', function(){
        console.log('user disconnected  ' + socket.username);
        delete users_online[socket.username];
    });
    
    socket.on('nearme', function(msg){
        var location = msg.location;
        socket.broadcast.emit(location, msg);
    });

    socket.on('region', function(msg){
        var location = msg.location.substring(msg.location.indexOf(",") + 1);
        socket.broadcast.emit(location, msg);
    });

    socket.on('private', function(msg, callback){
        var username = msg.username;
        var usernameTo = msg.usernameTo;
        var message = msg.message;
        var list = io.sockets.sockets;
        
        if(users_online[usernameTo] != null){
            if(list[users_online[usernameTo]] != null){
                socket.broadcast.to(users_online[usernameTo]).emit('message', msg);
                callback("Successful");
            }
        }else{
            var code = checkOnMessage(msg);
            switch(code) {
                case 0:
                    callback("Offline");
                    break;
                case 500:
                    callback("Error");
                    break;
                default:
                    callback("Successful");
            }
        }
    });
});

http.listen(process.env.PORT, function(){
    console.log('listening on port ' + process.env.PORT);
});

app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(bodyParser.json());
app.use(busboy());

app.set('view engine', 'ejs');

app.use(require('express').static(__dirname+ '/public'));


/* 
 * Middleware to use for requests
 */
app.use(function(request, response, next) {
    var currentUrl = (request.originalUrl);
    if(request.query.username != null){
                
        var username =  decodeURIComponent(request.query.username);
        var user_token = request.query.api_token;
        pool.getConnection(function (err, connection){
            if(err) {
                if(connection != null){
                    connection.release();
                }
                response.json({message : err, code : 500});
                response.end();
            }
            
            connection.query('SELECT * FROM users WHERE username = ?' , [username], function(err, result, fields) {
                connection.release();
                if (!err){
                    if(result.length > 0){
                        if(user_token == result[0].api_token){
                            next();
                        }else{
                            response.json({message : "Token not valid: Login again", code : 400});
                            response.end();
                        }
                    }else{
                        response.json({message : "Username doesnt exist", code : 404});
                        response.end();
                    }
                }else{
                    response.json({message : "User not authorize", code : 401});
                    response.end();
                }
            });
        });
    }else{
        next();
    }
});

app.get('/', function(req, res){
    //res.sendFile(__dirname + '/index.html',{name : "example"});
    res.render('profile',{name : "example"});
});

app.get('/resume', function(request, response){
    var file = __dirname + "/public/documents/Resume.pdf";
    fs.readFile(file, function(err, data){
        response.contentType("application/pdf");
        response.send(data);
        response.end();
    });
});

app.get('/chatogo', function(req, res){
    res.render('index',{name : "example"});
});

app.get('/api/publickey', function(req, response){
    response.json({publicKey : gPublicKey, code : 200});
    response.end();
});

app.get('/api/logout', function(request, response){
        console.log(request.query.username);
    var username = decodeURIComponent(request.query.username);
    pool.getConnection(function (err, connection) {
        if(err) {
            connection.release();
            response.json({message : err, code : 500});
            response.end();
        }
        
        connection.query('UPDATE users SET client_id = ? WHERE username = ?' ,
        ['offline', username], function(err, result) {
            connection.release();
            if(!err){
                response.json({message : "Logout successfully", code : 200});
                response.end();
            }else{
                response.json({message : "Logout failed", code : 400});
                response.end();
            }        
        });
    });
});

app.post('/api/login', function(request, response){
    var password = key.decrypt(request.body.password,"utf8");
    var username = key.decrypt(request.body.username,"utf8");
    var client_id = request.body.client_id;
    
    pool.getConnection(function (err, connection){
        if(err) {
            connection.release();
            response.json({message : err, code : 500});
            response.end();
        }
        
        connection.query('SELECT * FROM users WHERE username = ?' , [username], function(err, result) {
            if(!err){
                if(result.length > 0){
                    if(bcrypt.compareSync(password, result[0].password)){
                        connection.query('UPDATE users SET status = ?, client_id = ? WHERE username = ?' ,
                        ["available", client_id, username], function(err, result) {
                            if (!err){
                                console.log('Updated token successfully');
                            }
                        });
                        connection.release();
                        response.json({user: result[0], token: result[0].api_token, message : "Login successfully", code : 200});
                        response.end(); 
                    }else{
                        connection.release();
                        response.json({message : "Wrong Password", code : 401});
                        response.end()
                    }
                }else{
                    connection.release();
                    response.json({message : "Username doesnt exist", code : 404});
                    response.end();
                }
            }else{
                connection.release();
                console.log('Error while performing Query.');
                response.json({message : "Something went wrong", code : 400});
                response.end();
            }
        });
    });
});

app.post('/api/register', function(request, response){
    var password = key.decrypt(request.body.password,"utf8");
    var username = key.decrypt(request.body.username,"utf8");

    pool.getConnection(function (err, connection){
        if(err) {
            connection.release();
            response.json({message : err, code : 500});
            response.end();
        }
        
        connection.query('SELECT * FROM users WHERE username = ?' , [username], function(err, result) {
            if (!err){
                if(result.length > 0){
                    connection.release();
                    response.json({message : "Username already exist", code : 404});
                    response.end();
                }else{
                    connection.query('INSERT INTO users (status, username, password, api_token, client_id, profile_pic, location) VALUES(?,?,?,?,?,?,?)',
                    ["offline", username, bcrypt.hashSync(password, 10),crypto.randomBytes(32).toString('hex'),'',request.body.profile_pic,request.body.location], function(err, result) {
                        if (!err){
                            if (!fs.existsSync(__dirname + "/public/download/"+ username)){
                                fs.mkdirSync(__dirname + "/public/download/"+ username);
                            }
                            connection.query('SELECT * FROM users WHERE username = ?' , [username], function(err, result) {
                                if (!err){
                                    connection.release();
                                    response.json({user: result[0], message : "Registered successfully", code : 201});
                                    response.end();  
                                }else{
                                    connection.release();
                                    response.json({message : "Something went wrong", code : 400});
                                    response.end();
                                }
                            });                                    
                        }else{
                            connection.release();
                            console.log("Error while performing Query.", err); 
                        }
                    });
                }
            }else{
                connection.release();
                console.log('Error while performing Query.');
                response.json({message : "Something went wrong", code : 400});
                response.end();
            }
        });
    });
});

app.route('/api/users')

    .put(function(request, response){
        var username = decodeURIComponent(request.query.username);
        pool.getConnection(function (err, connection){
            if(err) {
                connection.release();
                response.json({message : err, code : 500});
                response.end();
            }
            
            connection.query('SELECT * FROM users WHERE username = ?' , [username], function(err, result) {
                if(!err){
                    if(result.length > 0){
                        connection.query('UPDATE users SET status = ?, profile_pic = ?, location = ? WHERE username = ?' ,
                            ["available", request.body.profile_pic, request.body.location, username], function(err, result) {
                            if(!err){
                                connection.query('SELECT * FROM users WHERE username = ?' , [username], function(err, result) {
                                    if(!err){
                                        connection.release();
                                        response.json({user : result[0], message : "Profile updated successfully", code : 200});
                                        response.end();
                                    }else{
                                        connection.release();
                                        response.json({message : "Something went wrong", code : 400});
                                        response.end();
                                    }
                                });
                            }else{
                                connection.release();
                                response.json({message : "User update failed", code : 400});
                                response.end();
                            }
                        });
                    }else{
                        connection.release();
                        response.json({message : "Username doesnt exist", code : 404});
                        response.end();
                    }
                }else{
                    connection.release();
                    console.log("Error while performing Query.");
                    response.json({message : "Something went wrong", code : 400});
                    response.end();
                }
            });
        });
    })
    
    .get(function(request, response){
        var usernameR = decodeURIComponent(request.query.usernameR);
        pool.getConnection(function (err, connection){
            if(err) {
                connection.release();
                response.json({message : err, code : 500});
                response.end();
            }
            
            connection.query('SELECT * FROM users WHERE username = ?' , [usernameR], function(err, result) {
                connection.release();
                if(!err){
                    if(result.length > 0){
                        response.json({message : "User found", content: result[0], code : 200});
                        response.end();
                    }else{
                        response.json({message : "Username doesnt exist" , code : 404});
                        response.end();
                    }
                }else{
                    console.log("Error while performing Query.");
                    response.json({message : "Something went wrong", code : 400});
                    response.end();    
                }
            });
        });
    });

app.get('/api/recentusers', function (request, response){
    pool.getConnection(function (err, connection){
        if(err) {
            connection.release();
            response.json({message : err, code : 500});
            response.end();
        }
        
        connection.query('SELECT * FROM users ORDER BY id DESC LIMIT 20', function(err, result) {
            connection.release();
            if(!err){
                if(result.length > 0){
                    response.json({message : "Users found", content: result, code : 200});
                    response.end();
                }else{
                    response.json({message : "No users subscribed", code : 404});
                    response.end();
                }
            }else{
                console.log("Error while performing Query.");
                response.json({message : "Something went wrong", code : 400});
                response.end();    
            }
        });
    });
});
    
app.post('/api/upload', function (request, response) {
    var fstream;
    var usernameTo;
    var username = decodeURIComponent(request.query.username);
    request.pipe(request.busboy);
    
    request.busboy.on('field', function(fieldname, value, fieldnameTruncated, valTruncated, encoding, mimetype) {
        console.log("in field");
        usernameTo = key.decrypt(value,"utf8");
    });
    
    request.busboy.on('file', function (fieldname, file, filename) {
        console.log("Uploading: " + filename + "  " + usernameTo);
        if (!fs.existsSync(__dirname + "/public/download/"+ usernameTo + "/" + username)){
            fs.mkdirSync(__dirname + "/public/download/"+ usernameTo + "/" + username);
        }
        try{
            //Path where image will be uploaded username + "/" + usernameTo + "/" +
            fstream = fs.createWriteStream(__dirname + "/public/download/"+ usernameTo + "/" + username + "/" + filename);
            file.pipe(fstream);
            fstream.on('close', function () {    
                console.log("Upload Finished of " + filename);   
                response.json({message : filename, code : 200});
                response.end();              
            });
        }catch (e){    
            response.json({message : "Error: Something happen", code : 500});
            response.end(); 
        }
            
    });
});
    
app.get('/api/download', function(request, response){
    var usernameFrom = key.decrypt(request.headers.usernamefrom ,"utf8");
    var filename = key.decrypt(request.headers.filename,"utf8");
    var username = decodeURIComponent(request.query.username);
    console.log("Downloading: " + " " + usernameFrom + "   " + filename);
    
    //usernameTo = key.decrypt(value,"utf8");
    var file = __dirname + "/public/download/" + username + "/" + usernameFrom + "/" + filename;
    response.download(file, function (err) {
         if (err) {
              console.log(err);
              //res.status(err.status).end();
         }else {
             console.log('Sent:', filename);
        }
    });
});

function checkOnMessage(msg){
    var username = msg.username;
    var usernameTo = msg.usernameTo;
    var message = msg.message;
    var type = msg.type;
    //var username = key.decrypt(msg.username, "utf8");
    //var usernameTo = key.decrypt(msg.usernameTo, "utf8");
    pool.getConnection(function (err, connection){
        if(err) {
            connection.release();
            response.json({message : err, code : 500});
            response.end();
        }
        
        connection.query('SELECT * FROM users WHERE username = ?' , [usernameTo], function(err, result) {
            connection.release();
            if (!err){
                if(result[0].client_id != "offline"){
                    var code = sendNotificationToUser(result[0], username, message, type);
                    return code;
                }else{
                    return 0;
                }
            }else{
                console.log("Error while performing Query.");
                return 500;
            }
             
        });
    });
    
}

function sendNotificationToUser(userTo, username, message, type) {
    var code = 200;
    request({
        url: 'https://fcm.googleapis.com/fcm/send',
        method: 'POST',
        headers: {
            'Content-Type' : 'application/json',
            'Authorization': 'key=' + API_KEY
        },
        body: JSON.stringify({
            data : {
                type : type,
                id  : userTo.id,
                username : username,
                message : message,
                usernameTo : userTo.username
            },
            to : userTo.client_id
        })
    }, 
    function(error, response, body) {
        if (error || (response.statusCode >= 400)) {
            code = 500;
            //'HTTP Error: '+response.statusCode+' - '+response.statusMessage
        }
        else {
            code = 200;
        }
    });
    return code;
}
    