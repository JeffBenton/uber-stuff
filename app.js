var express = require("express");
var path = require("path");
var bodyParser = require("body-parser");
var session = require('express-session');
var passport = require('passport');
var uberStrategy = require('passport-uber');
var https = require('https');
var http = require('http');
var config = require('./config.js');
var Uber = require('node-uber');
var twilio = require('twilio');
var qs = require('querystring');
var ejs = require('ejs');
var request = require('request');
var cheerio = require('cheerio');
var fs = require('fs');
//Geocoder stuff
var geocodeProvider = 'google';
var httpAdapter = 'https';
var extra = {
    apiKey: "",
    formatter: null
};
var geocoder = require('node-geocoder')(geocodeProvider, httpAdapter, extra);

var app = express();
var clientID = config.ClientID;
var clientSecret = config.ClientSecret;
var ServerID = config.ServerID;
var sessionSecret = "UBERAPIROCKS";
var globalAccessToken;
var uber = new Uber({
  client_id: clientID,
  client_secret: clientSecret,
  server_token: ServerID,
  redirect_uri: "http://localhost:8000/auth/uber/callback",
  name: 'Textber'
});
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "./client")));
app.set('view engine', 'ejs');

var server = app.listen(8000);
var io = require("socket.io").listen(server);



var url = 'https://uberforall.herokuapp.com/results';
var address_data;
var from_data;
var count_req = 0;
var old_count_req = 0;

var hasData = false;
function scrape(){
    if(!hasData){
        request(url, function(error, response, html){

            if(!error){
                var $ = cheerio.load(html);

                $('.address').filter(function(){
                    var data1 = $(this);
                    address_data = data1.text();
                });

                $('.from_data').filter(function(){
                    var data2 = $(this);
                    from_data = data2.text();
                });

                $('.number_request').filter(function(){
                    var data3 = $(this);
                    count_req = data3.text();

                    if (count_req != old_count_req) {

                        old_count_req = count_req;
                        console.log(count_req);
                        io.emit("has_changed",count_req);
                    }

                });
            }
        });
    }
}

var accountSid = 'AC23d38d64f113cbd57fe69b744ae37c46';
var authToken = '4767a1a13814d3e80b13773824e79f44';
var client = require('twilio')(accountSid, authToken);

client.messages.create({
    body: "Send me a response, prease",
    to: "+19142835331",
    from: "+16505420611"
}, function(err, message) {
    process.stdout.write(message.sid);
});

setInterval(function() {scrape()}, 1000);

app.post('/processtext', ensureAuthenticated, function(request,response) {
        var inputText = address_data;
        var splitText = inputText.split(":");
        var trip = [];
        var tripInfo = {};
        geocoder.geocode(splitText[0], function(err, res){
            trip.push({ lat: res[0].latitude, long: res[0].longitude });
            geocoder.geocode(splitText[1], function(err, res){
                trip.push({ lat: res[0].latitude, long: res[0].longitude });
                console.log(trip);
                var params = {
                    start_latitude : trip[0].lat,
                    start_longitude: trip[0].long,
                    end_latitude: trip[1].lat,
                    end_longitude: trip[1].long
                };
                uber.estimates.price(params, function(err, res){
                    console.log(res.prices[0]);
                    tripInfo.priceEstimate = res.prices[0].estimate;

                    uber.estimates.time(params, function(err, res){
                        console.log(res.times[0]);
                        tripInfo.timeEstimate = Math.ceil(res.times[0].estimate/60)
                        params.product_id = "a1111c8c-c720-46c3-8534-2fcdd730040d"

                        postAuthorizedRequest('/v1/requests', request.user.accessToken, params, function (error, res) {
                            if (error) { console.log(error); }
                            console.log(tripInfo); 
                            // response.redirect('triptracker');
                            client.messages.create({
                                body: "Your car has been dispatched!  Your price estimate is: " + tripInfo.priceEstimate + " and your car will arrive in " + tripInfo.timeEstimate + " minutes. Thank you for choosing Uber.",
                                to: "+19142635538",
                                from: "+16505420611"
                            }, function(err, message) {
                                    process.stdout.write(message.sid);
                                    response.redirect('/triptracker');
                                });
                         },  request);
                        });
                    });
                });
            });
});


passport.serializeUser(function (user, done){
    done(null, user);
});
passport.deserializeUser(function (user, done){
    done(null, user);
});
passport.use(new uberStrategy({
        clientID: clientID,
        clientSecret: clientSecret,
        callbackURL: "http://localhost:8000/auth/uber/callback"
    },
    function (accessToken, refreshToken, user, done) {
        user.accessToken = accessToken;
        return done(null, user);
    }
));


app.get('/triptracker', function (request, response) {
  response.render('triptracker');
});

// get request to start the whole oauth process with passport
app.get('/auth/uber',
    passport.authenticate('uber',
        { scope: ['profile', 'request', 'request_receipt'] }
    )
);
// authentication callback redirects to /login if authentication failed or home if successful
app.get('/auth/uber/callback',
    passport.authenticate('uber', {
        failureRedirect: '/login'
    }), function(req, res) {
        // globalAccessToken = req.user.accessToken;
    res.redirect('/');
  });

app.post("/addUser", function(request, response){
    console.log("here");
    client.messages.create({
        body: "Thank you for registering!",
        to: "+19142635538",
        from: "+16505420611"
    }, function(err, message) {
        process.stdout.write(message.sid);
    });
    response.redirect("/");
});

app.get('/', ensureAuthenticated, function (request, response) {
    response.render('index');
});


// ride request API endpoint
app.post('/request', ensureAuthenticated, function (request, response) {
    var parameters = {
        start_latitude : request.body.start_latitude,
        start_longitude: request.body.start_longitude,
        end_latitude: request.body.end_latitude,
        end_longitude: request.body.end_longitude,
        product_id: "a1111c8c-c720-46c3-8534-2fcdd730040d"
    };
    postAuthorizedRequest('/v1/requests', request.user.accessToken, parameters, function (error, res) {
        if (error) { console.log(error); }
          response.redirect('/trackRide'); 
    },  request);
});

app.get('/currentRide', function(request, response) {
    console.log("here");
    getAuthorizedRequest('/v1/requests/' + request.user.request_id,  request.user.accessToken, function(error, res){
          response.send(res);
    });
});
app.get('/login', function (request, response) {
    response.render('login');
});
app.post('/changeStatus', function(request, response) {
    var parameters = {
        status : request.body.status,
      };

    putAuthorizedRequest('/v1/sandbox/requests/' + request.user.request_id,  request.user.accessToken, parameters, function(error, res){
          response.send(res);
    });
});
// route middleware to make sure the request is from an authenticated user
function ensureAuthenticated (request, response, next) {
  console.log('inside ensure Authenticated');
    if (request.isAuthenticated()) {
        return next();
    }
    response.redirect('/login');
}
// use this for an api get request
function getAuthorizedRequest(endpoint, accessToken, callback) {
  var options = {
    hostname: "sandbox-api.uber.com",
    path: endpoint,
    method: "GET",
    headers: {
      Authorization: "Bearer " + accessToken
    }
  }
  var req = https.request(options, function(res) {

    var responseParts = '';
    res.setEncoding('utf8');

    res.on('data', function (chunk) {
        responseParts += chunk;
    });
    res.on('end', function () {
        callback(null, JSON.parse(responseParts));
    });
  });
  req.end();
  req.on('error', function(err) {
    callback(err, null);
  });
}
// use this for an api post request
function postAuthorizedRequest(endpoint, accessToken, parameters, callback, request) {
    var options = {
        hostname: "sandbox-api.uber.com",
        path: endpoint,
        method: "POST",
        headers: {
            Authorization: "Bearer " + accessToken,
            'Content-Type': 'application/json'
        }
    };
    var req = https.request(options, function(res) {
        var responseParts = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            responseParts += chunk;
        });
        res.on('end', function () {
            var request_id = 0;
            request_id = JSON.parse(responseParts).request_id;
            request.user.request_id = request_id;
            callback(null, JSON.parse(responseParts));
        });
    });
    req.write(JSON.stringify(parameters));
    req.end();
    req.on('error', function(err) {
        callback(err, null);
    });
}
function putAuthorizedRequest(endpoint, accessToken, parameters, callback, request) {
    var options = {
        hostname: "sandbox-api.uber.com",
        path: endpoint,
        method: "PUT",
        headers: {
            Authorization: "Bearer " + accessToken,
            'Content-Type': 'application/json'
        }
    };
    var req = https.request(options, function(res) {
        res.on('data', function(data) {
            callback(null, JSON.parse(data));
        });
    });
    req.write(JSON.stringify(parameters));
    req.end();
    req.on('error', function(err) {
        callback(err, null);
    });
}