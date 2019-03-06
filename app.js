// Configure and set dotenv.
require('dotenv').config();

var passport = require('passport'),
    saml     = require('passport-saml'),
    fs       = require('fs');

// Read the IdP Cert from the filesystem. 
// Uncomment this line if you want to validate the response with the cert.
// var idpCert = fs.readFileSync('./idp-cert.pem', 'utf-8');
var idpCert = '';

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

const PORT = process.env.PORT || 8080;

// Local server URL.
let localServerURL = process.env.SERVER_HOST + ":" + PORT;

let defaultCallbackUrl = localServerURL + process.env.SAML_CALLBACK_PATH;
let defaultLogoutCallback = localServerURL + '/logout/callback';
let relayStateUrl = localServerURL + '/relay';

// Setup the SAML strategy for the SSO process.
// To add RelayState to the original request we can add:
// additionalParams  : {
//   'RelayState' : 'http://localhost:4000'
// },
var samlStrategy = new saml.Strategy({
  callbackUrl       : defaultCallbackUrl,
  entryPoint        : process.env.IDP_ENTRYPOINT,
  issuer            : process.env.SP_ENTITYID,
  identifierFormat  : process.env.IDENTIFIER,
  cert              : idpCert,
  logoutUrl         : process.env.IDP_LOGOUT,
  logoutCallbackUrl : defaultLogoutCallback
}, function (profile, done) {
  if (!profile) {
    return done(new Error('SSO failed'), null);
  } else {
    return done(null, profile);
  }  
});

passport.use(samlStrategy);

var express = require('express'),
    app     = express(),
    bp      = require('body-parser'),
    session = require('express-session')
    router  = express.Router();

app.set('title', 'Passport SAML Tutorial');    

// Need this for passport to decode the response and read it.
app.use(bp.urlencoded({ extended : true }));

// Use Express session to pass the request from between pages.
app.use(session({
  secret            : 'supersecret',
  saveUninitialized : true,
  resave            : true
}));

app.use(passport.initialize());
app.use(passport.session());

// Setup the Template Engine.
app.set('view engine', 'pug');

// Default home page route.
router.get('/', function (request, response) {
  response.render('home', {
    header : 'Using Express Router'
  });
});

// Redirect to the IdP Login page.
router.get('/login', 
  passport.authenticate('saml', {
    successRedirect : '/loggedin',
    failureRedirect : '/login/fail'
  })
);

// Redirect the user to the relay state URL.
router.get('/relay', (request, response) => {
  if (request.isAuthenticated()) {
    console.log('The user is', request.user);
    response.status(200).send('User is ' + request.user.username);
  } else {
    response.redirect('/login');
  }
});

// Handle the Logged in user route.
router.get('/loggedin', function (request, response) {
  if (request.isAuthenticated()) {
    response.render('loggedin', {
      user : request.user
    });
  } else {
    response.redirect('/login');
  }
});

router.get('/login/fail', function (request, response) {
  response.status(200).send('Could not login.');
});

// Using Single Logout
router.get('/logout', (request, response) => {
  // requestUrl is the actual SAML SLO URL.
  samlStrategy.logout(request, function (err, requestUrl) {
    request.logout();
    response.redirect(requestUrl);
  });
});

// Handle the SAML callback URL.
router.post(process.env.SAML_CALLBACK_PATH, 
  passport.authenticate('saml', {
    failureRedirect : '/login/fail',
    failureFlash    : true
  }), function (request, response) {
    let relayState = request.query && request.query.RelayState || request.body && request.body.RelayState;
    if (relayState !== null && relayState !== undefined && relayState !== '') {
      response.redirect(relayState);
    } else {
      response.redirect('/loggedin');
    }
  }
);

// The callback for the SLO.
router.post('/logout/callback', function (request, response) {
  request.logout();
  response.redirect('/');
});

// Get the SP Metadata using this location.
router.get('/metadata', function (request, response) {
	response.type('application/xml');
	response.status(200).send(samlStrategy.generateServiceProviderMetadata());
});

// Catch all other routes not defined above.
router.get('*', function (request, response) {
  response.status(404).render('404');
});

app.use('/', router);

// Start the Express server.
app.listen(PORT, function () {
  console.log('Express server is up and running and listening on', PORT);
});
