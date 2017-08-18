var _ = require('lodash');
var fs = require('fs');
var express = require('express');
var bodyParser = require('body-parser');
var bunyan = require('bunyan');
var request = require('request');
var jwtUtil = require('jwt-simple')
var logger = bunyan.createLogger({
    name: 'hc-sample-addon', level: 'info'
});
var Songwhip = require('./song-whip.js');

var app = express();
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

//Store for all add-on installations (OAuthID, shared secret, API baseUrl, etc.)
// if it is in local storage, then load it.
var installationStore = {};
//Store for API access tokens, used when making REST calls to HipChat
var accessTokenStore = {};


// var whipSongCallbackd = function(songWhipObject) {
//     console.log(songWhipObject);
//     if(songWhipObject.getSongName()) {
//         var echoMessage = "<b>Song:</b> " + songWhipObject.getArtistName() + " - " + songWhipObject.getSongName();
//         echoMessage = echoMessage + "<br/>";

//         var links = songWhipObject.getLinks();
//         for(var property in links) {
//             if(links.hasOwnProperty(property)) {
//                 console.log(property);
//                 echoMessage = echoMessage + "<a href='" + songWhipObject.getLinkUrl(property) + "'>"+capitalizeFirstLetter(property)+"</a><br/>";
//             }
//         }
//     }
        
//         console.log(echoMessage);
// }

// var songwhip = new Songwhip('https://open.spotify.com/track/1opaDJsJXDmjCWv7lNTgnM', whipSongCallbackd);
// songwhip.run();
   

app.post('/whipsong', validateJWT, //will be executed before the function below, to validate the JWT token
    function(req, res) {

        logger.info({message: message, q: req.query}, req.path);
        var message = req.body;

        var whipSongCallback = function(songWhipObject) {
            if(songWhipObject.getSongName()) {
                var echoMessage = "<b>Song:</b> " + songWhipObject.getArtistName() + " - " + songWhipObject.getSongName();
                echoMessage = echoMessage + "<br/>";

                var links = songWhipObject.getLinks();
                for(var property in links) {
                    if(links.hasOwnProperty(property)) {
                        echoMessage = echoMessage + "<a href='" + songWhipObject.getLinkUrl(property) + "'>"+capitalizeFirstLetter(property)+"</a><br/>";
                    }
                }

                sendHtmlMessage(res.locals.context.oauthId, res.locals.context.roomId, echoMessage);
            }

        }

        var hipchatMessage = message['item']['message']['message']
        var urls = hipchatMessage.match(/\bhttps?:\/\/\S+/gi);

        if(urls) {
            urls.forEach(function(element)
            {
                var songwhip = new Songwhip(element, whipSongCallback);
                songwhip.run();
            });
            // we expect the message to contain only the url for now, needs some regular expressing soon.
        }

        res.sendStatus(204);
    });

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

// everything down here is copied from demo project, to make it work.

/**
 * Your add-on exposes a capabilities descriptor , which tells HipChat how the add-on plans to extend it.
 *
 * This add-on's capability descriptor can be found here: /capabilities.json
 * The variable ${host} is substituted based on the base URL of your add-on.
 */
function substituteHostName(file, req, callback) {
    fs.readFile(file, function(err, data) {
        var content = _.template(data, {
            host: 'https://' + req.headers.host
        });
        callback(content);
    });
}

function sendDescriptor(file, req, res) {
    substituteHostName(file, req, function(content) {
        res.set('Content-Type', 'application/json');
        res.send(content);
    });
}

app.get('/descriptor', function(req, res) {
    sendDescriptor('capabilities-descriptor.json', req, res);
});

/**
 * In order for your add-on to be installed in HipChat, it needs to implement the HipChat add-on installation flow.
 * When a user installs or uninstalls your add-on, HipChat makes a REST call to an endpoint specified in the capabilities descriptor:
 *       "installable": {
 *           "allowGlobal": true,
 *           "allowRoom": true,
 *           "callbackUrl": "${host}/installed",
 *           "uninstalledUrl": "${host}/uninstalled"
 *       }
 * At installation, HipChat sends installation data: OAuth ID, shared secret, URLs to use to make REST calls, contextual information.
 * You need to store this information for later use.
 */

app.post('/installed', function(req, res) {
    logger.info(req.query, req.path);

    var installation = req.body;
    var oauthId = installation['oauthId'];
    installationStore[oauthId] = installation;

    // Retrieve the capabilities document
    var capabilitiesUrl = installation['capabilitiesUrl'];
    request.get(capabilitiesUrl, function(err, response, body) {
        var capabilities = JSON.parse(body);
        logger.info(capabilities, capabilitiesUrl);

        // Save the token endpoint URL along with the client credentials
        installation.tokenUrl = capabilities['capabilities']['oauth2Provider']['tokenUrl'];

        // Save the API endpoint URL along with the client credentials
        installation.apiUrl = capabilities['capabilities']['hipchatApiProvider']['url'];

        res.sendStatus(200);
    });

});

app.get('/uninstalled', function(req, res) {
    logger.info(req.query, req.path);
    var redirectUrl = req.query['redirect_url'];
    var installable_url = req.query['installable_url'];

    request.get(installable_url, function(err, response, body) {
        var installation = JSON.parse(body);
        logger.info(installation, installable_url);

        delete installationStore[installation['oauthId']];
        delete accessTokenStore[installation['oauthId']];

        // Redirect back to HipChat to complete the uninstallation
        res.redirect(redirectUrl);
    });
});

function isExpired(accessToken) {
    return accessToken.expirationTimeStamp < Date.now();
}

function refreshAccessToken(oauthId, callback) {
    var installation = installationStore[oauthId];
    var params = {
        // The token url was discovered through the capabilities document
        uri: installation.tokenUrl, // Basic auth with OAuth credentials received on installation
        auth: {
            username: installation['oauthId'], password: installation['oauthSecret']
        }, // OAuth dictates application/x-www-form-urlencoded parameters
        // In terms of scope, you can either to request a subset of the scopes declared in the add-on descriptor
        // or, if you don't, HipChat will use the scopes declared in the descriptor
        form: {
            grant_type: 'client_credentials', scope: 'send_notification'
        }
    };
    logger.info(params, installation.tokenUrl);

    request.post(params, function(err, response, body) {
        var accessToken = JSON.parse(body);
        logger.info(accessToken, installation.tokenUrl);
        accessTokenStore[oauthId] = {
            // Add a minute of leeway
            expirationTimeStamp: Date.now() + ((accessToken['expires_in'] - 60) * 1000), token: accessToken
        };
        callback(accessToken);
    });
}

function getAccessToken(oauthId, callback) {
    var accessToken = accessTokenStore[oauthId];
    if(!accessToken || isExpired(accessToken)) {
        refreshAccessToken(oauthId, callback);
    }
    else {
        process.nextTick(function() {
            callback(accessToken.token);
        });
    }
}

/**
 * Sending messages to HipChat rooms
 * ---------------------------------
 * You send messages to HipChat rooms via a REST call to the room notification endpoint
 * HipChat supports various formats for messages, and here are a few examples:
 */

function sendMessage(oauthId, roomId, message) {
    var installation = installationStore[oauthId];
    var notificationUrl = installation.apiUrl + 'room/' + roomId + '/notification';
    getAccessToken(oauthId, function(token) {
        request.post(notificationUrl, {
            auth: {
                bearer: token['access_token']
            }, json: message
        }, function(err, response, body) {
            logger.info(err || response.statusCode, notificationUrl);
            logger.info(response);
        });
    });
}

function sendHtmlMessage(oauthId, roomId, text) {
    var message = {
        color: 'purple', message: text, message_format: 'html'
    };
    sendMessage(oauthId, roomId, message)
}

/**
 * Securing your add-on with JWT
 * -----------------------------
 * Whenever HipChat makes a call to your add-on (webhook, glance, views), it passes a JSON Web Token (JWT).
 * Depending on the scenario, it is either passed in the "signed_request" URL parameter, or the "Authorization" HTTP header.
 * This token contains information about the context of the call (OAuth ID, room ID, user ID, etc.)
 * This token is signed, and you should validate the signature, which guarantees that the call really comes from HipChat.
 * You validate the signature using the shared secret sent to your add-on at installation.
 *
 * It is implemented as an Express middleware function which will be executed in the call chain for every request the add-on receives from HipChat
 * It extracts the context of the call from the token (room ID, oauth ID) and adds them to a local variable accessible to the rest of the call chain.
 */

function validateJWT(req, res, next) {
    try {
        logger.info('validating JWT');

        //Extract the JWT token
        var encodedJwt = req.query['signed_request'] || req.headers['authorization'].substring(4) || req.headers['Authorization'].substring(4);

        // Decode the base64-encoded token, which contains the oauth ID and room ID (to identify the installation)
        var jwt = jwtUtil.decode(encodedJwt, null, true);
        var oauthId = jwt['iss'];
        var roomId = jwt['context']['room_id'];
        var installation = installationStore[oauthId];
        // Validate the token signature using the installation's OAuth secret sent by HipChat during add-on installation
        // (to ensure the call comes from this HipChat installation)
        jwtUtil.decode(encodedJwt, installation.oauthSecret);

        //all good, it's from HipChat, add the context to a local variable
        res.locals.context = {oauthId: oauthId, roomId: roomId};

        // Continue with the rest of the call chain
        logger.info('Valid JWT');
        next();
    } catch(err) {
        logger.info(err);
        logger.info('Invalid JWT');
        res.sendStatus(403);
    }
}



/**
 * Add-on configuration page
 * -------------------------
 * Post installation, your add-on can show the user a configuration page
 * Your add-on declares it in its capability descriptor
 *    "configurable": {
 *            "url": "${host}/configure"
 *      }
 */

app.get('/configure', validateJWT, function(req, res) {
    logger.info(req.query, req.path);
    res.send("This is a configuration page for your add-on");
});

/*
 * Start the add-on
 */
app.all('*', function(req, res) {
    logger.info({body: req.body, q: req.query}, req.path);
    res.sendStatus(204);
});

var port = 4000;
app.listen(port);
logger.info('HipChat sample add-on started: http://localhost:' + port);