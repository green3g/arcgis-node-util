require('isomorphic-fetch');
require('isomorphic-form-data');
const { UserSession } = require('@esri/arcgis-rest-auth');
const express = require('express');
const passport = require('passport');
const ArcGISStrategy = require('passport-arcgis').Strategy;
const debug = require('debug')('arcgis:oauth');
const open = require('open');

/**
 * @typedef  {Object} auth/oauth~AuthOptions
 * @property {String} appId App ID for the authenticating application.
 * @property {String} secret (optional) Secret key for authenticating application.
 * Used if you need to access credit based resources.
 * @property {Number} port The port number for the server. Default is `3000`.
 * @property {String} url The url for the server. Default is `http://lvh.me`.
 * @property {String} portalUrl The url for the authenticating portal. Default is `https://maps.arcgis.com`
 */
const defaults = {
  appId: 'appId',
  secret: '123',
  port: 3000,
  url: 'http://lvh.me',
  portalUrl: 'https://maps.arcgis.com',
};

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});


/**
 * Authenticate with arcgis portal/ago using
 * an oauth workflow.
 * 1. Spin up a Express app with an `/authenticate` endpoint
 * 2. Direct user to authentication endpoint to begin oauth
 * 3. After successful authentication, return user to `/callback` with authorization code
 * 4. Shut down express server and return a code
 * @see https://esri.github.io/arcgis-rest-js/api/auth/UserSession/#exchangeAuthorizationCode
 * @function auth/oauth
 * @param {auth/oauth~AuthOptions} options Auth options
 * @returns {Promise<UserSession>}
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
    authorizationURL: `${props.portalUrl}/oauth2/authorize`,
    tokenURL: `${props.portalUrl}/oauth2/token`,
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
    portal: props.portalUrl,
  }, code));
}

module.exports = authenticate;
