require('isomorphic-fetch');
require('isomorphic-form-data');
const express = require('express');
const passport = require('passport');
const ArcGISStrategy = require('passport-arcgis').Strategy;
const debug = require('debug')('arcgis:oauth');
const openBrowser = require('open');
import {
  UserSession
} from "@esri/arcgis-rest-auth";


export interface OauthOptions {
  /**
   * App ID for authenticating application 
   */
  appId: string;
  /**
   * The url for the authenticating portal (default: 'https://maps.arcgis.com')
   */
  portalUrl ? : string;
  /**
   * Port for oauth server (default: 3000)
   */
  port ? : number;
  /**
   * URL for oauth  server (default: 'http://lvh.me')
   */
  url ? : string;
  /**
   * Optional secret for authenticating app
   */
  secret ? : string;
  /**
   * Timeout (in milleseconds) to automatically kill server
   * and reject promise (default: 30000)
   */
  rejectionTimeout?: number;
  /**
   * Timeout (in milleseconds) to automatically kill server
   * after successful auth result (default: 500)
   */
  successTimeout?: number;
}


// shut down server after 500 ms
const SUCCESS_TIMEOUT = 500;

// Fail authentication after 30 s
const REJECTION_TIMEOUT = 30000;

const defaults: OauthOptions = {
  appId: 'appId',
  secret: '123',
  port: 3000,
  url: 'http://lvh.me',
  portalUrl: 'https://maps.arcgis.com',
  rejectionTimeout: REJECTION_TIMEOUT,
  successTimeout: SUCCESS_TIMEOUT,
};

passport.serializeUser((user: any, done: any) => {
  done(null, user);
});

passport.deserializeUser((obj: any, done: any) => {
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
 *
 * @example
 * authenticate({
 *    appId: 'XYZ123,
 *    portalUrl: 'https://my-domain.com/portal',
 * }).then(userSession => console.log(userSession));
 */
export function authenticate(options: OauthOptions): Promise < UserSession > {

  const props: OauthOptions = {
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
    (accessToken: string, refreshToken: string, profile: any, done: any) => done(null, profile),
  ));

  return new Promise((resolve, reject) => {
    // initialize server
    let server: { close: () => void; };
    const app = express();


    // auto time out after an amount of time
    const rejectionTimeout = setTimeout(() => {
      server.close();
      reject(new Error('User failed to authenticate in the required time'));
    }, options.rejectionTimeout)


    app.use(passport.initialize());
    app.use('/authenticate', passport.authenticate('arcgis'));
    app.use('/callback', passport.authenticate('arcgis'), (result: {
      query: {
        code: unknown;
      };
    }, response: {
      send: (arg0: string) => void;
    }) => {
      // remove rejection timeout
      clearTimeout(rejectionTimeout);

      // auto stop server in a few milliseconds
      setTimeout(() => server.close(), options.successTimeout || SUCCESS_TIMEOUT);

      if (result.query.code) {
        response.send('Login successful! You may now close this page<br /><a href="#" onclick="javascript:window.close();">Close Window</a>');
        resolve(result.query.code);
      } else {
        response.send('Error! No login code was passed');
        reject(new Error('No oauth token retrieved, please try again'));
      }
    });

    server = app.listen(props.port, () => {
      const endpoint = `${props.url}:${props.port}/authenticate`;
      debug(`Token app listening on ${endpoint}`);
      openBrowser(endpoint);
    });

  }).then((code) => {
    return UserSession.exchangeAuthorizationCode({
      clientId: props.appId,
      redirectUri: passportOptions.callbackURL,
      portal: props.portalUrl,
    }, code as string)
  });
}