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

// Setup the SAML strategy for the SSO process.
var samlStrategy = new saml.Strategy({
  callbackUrl : process.env.SERVER_HOST + process.env.SAML_CALLBACK_PATH,
  entryPoint  : process.env.IDP_ENTRYPOINT,
  issuer      : process.env.SP_ENTITYID,
  cert        : idpCert
}, function (profile, done) {
  if (!profile) {
    console.log('Inside the error section');
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

router.get('/logout', function (request, response) {
	request.session.destroy();
	response.redirect(process.env.IDP_LOGOUT + '?goto=' + process.env.SERVER_HOST);
});

// Handle the SAML callback URL.
router.post(process.env.SAML_CALLBACK_PATH, 
  passport.authenticate('saml', {
    failureRedirect : '/login/fail',
    failureFlash    : true
  }), function (request, response) {
    response.redirect('/loggedin');
  }
);

// Get the SP Metadata using this URL.
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
app.listen(process.env.PORT, function () {
  console.log('Express server is up and running and listening on', process.env.PORT);
});
