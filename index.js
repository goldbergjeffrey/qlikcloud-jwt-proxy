import crypto from 'crypto';
import express from 'express';
import session from 'express-session';
import * as cookieParser from 'cookie-parser';
import * as cookie from 'cookie';
import RedisStore from 'connect-redis';
import {createClient} from 'redis';
import compression from 'compression';
import { generators } from 'openid-client';
import jsonwebtoken from 'jsonwebtoken';
import WebSocket, { WebSocketServer } from 'ws';
import { join } from 'path';

const __dirname = new URL('.', import.meta.url).pathname;

// Using JWT to authorize users to Qlik Cloud tenants requires a
// an active JWT identity provider configuration and certificates
// to sign and validate JWT tokens sent from this proxy code to
// your Qlik Cloud tenant.
// Review https://qlik.dev/authenticate/jwt/create-signed-tokens-for-jwt-authorization
// for JWT IdP configuration tutorials.
const qlikConfig = {
  tenantUri: process.env['tenantUri'], // Your Qlik Cloud tenant hostname like 'jwt-proxy.us.qlikcloud.com'
  privateKey: process.env['privateKey'].replaceAll('\\n', '\n'),
  keyId: process.env['keyId'],
  issuer: process.env['issuer']
};

// If you are embedding an iframe or using the capability API, you will need to
// create a web-integration-id in Qlik Cloud and add your web application to the
//allow list.
const qlikWebId = process.env['webIntegrationId'];

// This example contains an identity provider connection to approximate
// authenticating to a portal or web application. It is part of this example
// for demonstration purposes only.
// This example uses Auth0 as the identity provider to authenticate users to the
// front end application.
const clientId = process.env['clientId']
const clientSecret = process.env['clientSecret']
const redirectUri = process.env['redirectUri']
const idpAuthorizeUri = `${process.env['idpUri']}/authorize`;
const idpTokenUri = `${process.env['idpUri']}/oauth/token`;
const idpScope = 'openid email profile';

// This is a local storage object for mapping the state during the authentication
// steps in this example.
const tokenStore = {};

// This is the frontend application uri used for responding to requests.
const frontendUri = "https://qlikcloud-jwt-proxy.qlik.repl.co";

// This example uses express-session and redis to manage and 
// store sessions for this proxy. In this example, redis stores
// the ID token from the identity provider and the Qlik Cloud
// session cookie used when proxying requests from this web
// application to Qlik Cloud.
const sessionSecret = process.env['sessionSecret'];
const redis_db = process.env['redis_db'];
const redis_port = Number(process.env['redis_port']);
const redis_pwd = process.env['redis_pwd'];

// Create the connection to Redis. This example uses Redis cloud free tier.
const client = createClient({
    password: redis_pwd,
    socket: {
        host: redis_db,
        port: redis_port
    }
});

await client.connect();
const store = new RedisStore({ client: client });

// This example uses express.js to provide the proxy services between the
// frontend web application and Qlik Cloud REST endpoints and websocket
// connections to the engine.
const app = express();
app.use(compression({ threshold: 0 }));

// Add the session management component to the proxy. Adds a 1st-party cookie
// to manage a user's session.
app.use(session({
  store: store,
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: true,
    secure: false,
    httpOnly: false,
    maxAge: 1000 * 60 * 10 // 10 minutes
  }
}));

// send the webpage to the browser
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'))
})

// This endpoint is necessary for this example to authenticate a user.
// You may authenticate users in a different way and that is ok.
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex')
  const codeVerifier = generators.codeVerifier(43)
  const codeChallenge = generators.codeChallenge(codeVerifier)

  tokenStore[state] = { codeVerifier }
  res.redirect(
    `${idpAuthorizeUri}?response_type=code&prompt=none&client_id=${clientId}&redirect_uri=${redirectUri}&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=${idpScope}&state=${state}`
  )
  res.end()
})

// This endpoint is necessary for this example to authenticate a user
// if they went to the callback url direcly. If the user is authenticated,
// contact the token endpoint to obtain the id_token from the IdP.
// With the id_token, authorize the user to Qlik Cloud performing JWT auth.
// Register a session with the tokenstore so the application can proxy requests
// to Qlik Cloud as the correct user from the frontend through the backend.
// Redirect to the front end application to give it a session id and render
// content to the browser.
app.get('/login/callback', async (req, res) => {
  const session = req.session;
  const { code, error, state } = req.query
  if (error === 'login_required' || error === 'interaction_required') {
    const state2 = crypto.randomBytes(16).toString('hex')
    const codeVerifier = generators.codeVerifier(43)
    const codeChallenge = generators.codeChallenge(codeVerifier)

    tokenStore[state2] = { codeVerifier }
    res.redirect(
      `${idpAuthorizeUri}?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=${idpScope}&state=${state2}`
    )
    res.end()
    return
  }
  
  if (!tokenStore[state]) {
    console.log('state does not exist')
    res.status(401).end()
  }

  // If the user is authenticated, fetch the id_token from the web application
  // identity provider, map attributes to authenticate to Qlik Cloud and get a
  // session cookie, store it for the proxy to use, and redirect to the web
  // application frontend with a sessionid.
  const idpTokenRes = await fetch(`${idpTokenUri}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      code,
      code_verifier: tokenStore[state].codeVerifier,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
    }),
  });
  if (idpTokenRes.status === 200) {
    const idpToken = await idpTokenRes.json();
    const idToken = jsonwebtoken.decode(idpToken.id_token);

    // To obtain a qlik session cookie, the user's email, name, and subject
    // from the authenticated web application must be provided to Qlik.
    const qlikJwt = await createToken(idToken.email, idToken.name, idToken.sub, qlikConfig);
    const qlikSession = await getQlikSessionCookie(qlikConfig.tenantUri, qlikJwt);

    // Add the idToken and the Qlik Cloud cookie to the current session.
    // Encoding the strings ensures that when decoded no characters are changed,
    // therefore, reducing the chance of very hard to find errors.
    session.idToken = encodeURIComponent(idToken);
    session.qlikSession = encodeURIComponent(qlikSession);
    
    //redirect to your web application providing it with the sessionId.
    res.redirect(`${frontendUri}`);
  } else {
    console.log(await idpTokenRes.text());
  }

  res.end();
})

// Intercepts a request to the Single API (used for iframe embedding) and
// proxies the request to Qlik Cloud.
app.get('/single/*', async (req, res) => {
  const session = req.session;
  const path = req.originalUrl;
  const reqHeaders = {};
  if (session.id && session.qlikSession) {
    reqHeaders.cookie = decodeURIComponent(session.qlikSession);
    const csrfToken = reqHeaders.cookie.match('_csrfToken=(.*);')[1];
    const r = await fetch(`https://${qlikConfig.tenantUri}${path}&qlik-csrf-token=${csrfToken}&qlik-web-integration-id=${qlikWebId}`, {
      headers: reqHeaders,
    });
    setCors(res);
    res.set('content-type', 'text/html; charset=UTF-8');
    res.status(r.status);
    const buffer = Buffer.from(await r.arrayBuffer());
    res.end(buffer, 'binary');
  } else {
    setCors(res);
    res.end('no sessionId');
  }

  res.end("No sessionId or qlik session cookie");

});

// Intercepts a request to one of Qlik's REST APIs and proxies the request to
// Qlik Cloud.
app.get('/api/v1/*', async (req, res) => {
  const session = req.session;
  const reqHeaders = {};
  
  if (session.id && session.qlikSession) {
    reqHeaders.cookie = decodeURIComponent(session.qlikSession);
  }
  
  const r = await fetch(`https://${qlikConfig.tenantUri}${req.path}`, {
    headers: reqHeaders,
  });
  setCors(res);
  res.status(r.status);
  const buffer = Buffer.from(await r.arrayBuffer());
  res.end(buffer, 'binary');
});

// fetch resource from qlik using a redirect instead of proxy
// This endpoint is necessary when your web application uses the capability API.
app.get('/resources/*', async (req, res) => {
  setCors(res);
  res.redirect(`https://${qlikConfig.tenantUri}${req.path}`);
  res.end();
});

// Issues the necessary pre-flight request to make sure the browser
// knows how to work with the web application.
app.options('/*', async (req, res) => {
  setCors(res);
  res.status(200).end();
});

// Starts the server running this example.
const server = app.listen(3000, () => {
  console.log('Backend started');
})

// Websocket section for intercepting websocket requests from the
// frontend application. When the front end application communicates
// communicates with the backend using websockets, this set of
// functions will be invoked.
const wss = new WebSocketServer({ server })

wss.on('connection', async function connection(ws, req) {
  let isOpened = false
  // WebSockets do not have access to session information.
  // To get the session you need to parse the 1st-party cookie.
  // This will give you access to the Qlik Cloud cookie in order
  // to proxy requests.
  const cookieString = req.headers.cookie;
  let qlikCookie = '';
  if (cookieString) {
    const cookieParsed = cookie.parse(cookieString);
    const appCookie = cookieParsed['connect.sid'];
    if (appCookie) {
      const sidParsed = cookieParser.signedCookie(appCookie, sessionSecret);
       await store.get(sidParsed, (err, session) => {
        if (err) throw err;
        qlikCookie = decodeURIComponent(session.qlikSession);
      });
    }
  }

  const appId = req.url.match('/app/(.*)\\?')[1]
  const csrfToken = qlikCookie.match('_csrfToken=(.*);')[1]
  const qlikWebSocket = new WebSocket(`wss://${qlikConfig.tenantUri}/app/${appId}?qlik-csrf-token=${csrfToken}`, {
    headers: {
      cookie: qlikCookie,
    },
  })

  qlikWebSocket.on('error', console.error)
  const openPromise = new Promise((resolve) => {
    qlikWebSocket.on('open', function open() {
      resolve()
    })
  })

  ws.on('message', async function message(data) {
    if (!isOpened) {
      await openPromise
      isOpened = true
    }
    qlikWebSocket.send(data.toString())
  })

  qlikWebSocket.on('message', function message(data) {
    ws.send(data.toString())
  })
})

function setCors(res) {
  res.set('Access-Control-Allow-Origin', frontendUri)
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.set('Access-Control-Allow-Headers', 'Content-Type, x-proxy-session-id')
  res.set('Access-Control-Allow-Credentials', 'true')
}

// Create a JSON web token (JWT) to send to Qlik Cloud.
// The token will be used to authorize user to Qlik Cloud.
async function createToken(email, name, sub, config) {
  const signingOptions = {
    keyid: config.keyId,
    algorithm: 'RS256',
    issuer: config.issuer,
    expiresIn: '1m',
    audience: 'qlik.api/login/jwt-session',
    notBefore: '0s',
  };

  const payload = {
    jti: crypto.randomBytes(16).toString('hex'),
    sub: `BackendApp|${sub}`,
    subType: 'user',
    email_verified: true,
    email,
    name,
  };

  const token = jsonwebtoken.sign(payload, config.privateKey, signingOptions);
  return token;
}

// Use the JWT token to authorize the user to Qlik Cloud.
// Return the cookie that will be used to proxy requests to Qlik Cloud.
async function getQlikSessionCookie(tenantUri, token) {
  const resp = await fetch(`https://${tenantUri}/login/jwt-session`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  })

  if (resp.status === 200) {
    return resp.headers
      .get('set-cookie')
      .split(',')
      .map((e) => {
        return e.split(';')[0]
      })
      .join(';')
  }
  return ''
}
