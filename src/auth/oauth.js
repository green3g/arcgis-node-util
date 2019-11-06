require('isomorphic-fetch');
require('isomorphic-form-data');
const { UserSession } = require('@esri/arcgis-rest-auth');
const express = require('express');
const passport = require('passport');
const ArcGISStrategy = require('passport-arcgis').Strategy;
const debug = require('debug')('arcgis:oauth');
const open = require('open');


const defaults = {
  appId: 'appId',
  secret: '123',
  port: 3000,
  url: 'http://lvh.me',
  portalUrl: 'https://gregg-roemhildt.maps.arcgis.com',
};

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});


/**
 */
function authenticate(options) {
  const props = {
    ...defaults,
    ...options,
  };


  const passportOptions = {
    clientID: props.appId,
    clientSecret: props.secret,
    callbackURL: `${props.url}:${props.port}/callback`,
    authorizationURL: `${props.portalUrl}/sharing/oauth2/authorize`,
    tokenURL: `${props.portalUrl}/sharing/oauth2/token`,
  };

  passport.use(new ArcGISStrategy(
    passportOptions,
    (accessToken, refreshToken, profile, done) => done(null, profile),
  ));

  return new Promise((resolve, reject) => {
    let server;
    const app = express();

    app.use(passport.initialize());
    app.use('/authenticate', passport.authenticate('arcgis'));
    app.use('/callback', passport.authenticate('arcgis'), (result, response) => {
      setTimeout(() => server.close(), 5000);

      if (result.query.code) {
        response.send('Login successful! You may now close this page<br /><a href="#" onclick="javascript:window.close();">Close Window</a>');
        resolve(result.query.code);
      } else {
        response.send('Error! No login code was passed');
        reject(new Error('No oauth token retrieved'));
      }
    });
    server = app.listen(props.port, () => {
      const endpoint = `${props.url}:${props.port}/authenticate`;
      debug(`Token app listening on ${endpoint}`);
      open(endpoint);
    });
  }).then((code) => UserSession.exchangeAuthorizationCode({
    clientId: props.appId,
    redirectUri: passportOptions.callbackURL,
  }, code));
}

module.exports = authenticate;
