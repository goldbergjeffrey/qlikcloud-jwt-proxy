import crypto from 'crypto'
import express from 'express'
import compression from 'compression'
import { generators } from 'openid-client'
import jsonwebtoken from 'jsonwebtoken'
import WebSocket, { WebSocketServer } from 'ws'
import { join } from 'path'

const __dirname = new URL('.', import.meta.url).pathname

// Qlik Cloud configuration
const qlikConfig = {
  tenantUri: process.env['tenantUri'], // Your Qlik Cloud tenant hostname like 'jwt-proxy.us.qlikcloud.com'
  privateKey: process.env['privateKey'].replaceAll('\\n', '\n'),
  keyId: process.env['keyId'],
  issuer: process.env['issuer']
};

// Your web application's identity provider configuration
// This example uses Auth0 as the identity provider to authenticate users to the
// front end application. Your solution may use a different identity provider
// to authenticate users or you may add this code to a solution where users
// have an existing authenticated session to your web application.
const clientId = process.env['clientId']
const clientSecret = process.env['clientSecret']
const redirectUri = process.env['redirectUri']
const idpAuthorizeUri = `${process.env['idpUri']}/authorize`;
const idpTokenUri = `${process.env['idpUri']}/oauth/token`;
const idpScope = 'openid email profile';

// This is a local storage object for mapping Qlik Cloud session cookies with
// the user's identity provider token. The key for each object in the array is
// the sessionId used to proxy requests from the front-end to this backend proxy.
const tokenStore = {}

// This is the frontend application uri used for responding to requests.
const frontendUri = "https://jwt-proxy-combined.qlik.repl.co";

// This example uses express.js to provide the proxy services between the
// frontend web application and Qlik Cloud REST endpoints and websocket
// connections to the engine.
const app = express()
app.use(compression({ threshold: 0 }))

app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'))
})

app.get('/sw.js', (req, res) => {
  res.sendFile(join(__dirname, 'sw.js'))
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
  })
  if (idpTokenRes.status === 200) {
    const idpToken = await idpTokenRes.json()
    const idToken = jsonwebtoken.decode(idpToken.id_token)

    // To obtain a qlik session cookie, the user's email, name, and subject
    // from the authenticated web application must be provided to Qlik.
    const qlikJwt = await createToken(idToken.email, idToken.name, idToken.sub, qlikConfig);
    const qlikSession = await getQlikSessionCookie(qlikConfig.tenantUri, qlikJwt);

    // Create a unique identifier for the session so that the frontend and
    // backend can communicate and requests to Qlik proxy correctly.
    const frontendSession = crypto.randomBytes(16).toString('hex');
    tokenStore[frontendSession] = { idpToken, qlikSession };

    //redirect to your web application providing it with the sessionId.
    res.redirect(`${frontendUri}/?sessionId=${frontendSession}&name=${idToken.name}`)
  } else {
    console.log(await idpTokenRes.text())
  }

  res.end()
})

// Intercepts a request to the Single API (used for iframe embedding) and
// proxies the request to Qlik Cloud.
app.get('/single/*', async (req, res) => {
  const path = req.originalUrl
  const reqHeaders = {}
  const webId = "3nGykdFRwOGYQgShM3tZ87yQCbJQ6j0s";
  // if the request has a valid sessionId, retrieve the Qlik session cookie
  // and forward the response to Qlik Cloud.
console.log(path);
  //hatem
  if (req.url.match('sessionId=(.*)')) {
    console.log(req.url)
    const sessionId = req.url.match('sessionId=(.*)')[1]
    if (sessionId && tokenStore[sessionId]?.qlikSession) {
      reqHeaders.cookie = tokenStore[sessionId]?.qlikSession
      const csrfToken = reqHeaders.cookie.match('_csrfToken=(.*);')[1]
      const r = await fetch(`https://${qlikConfig.tenantUri}${path}&qlik-csrf-token=${csrfToken}&qlik-web-integration-id=${webId}`, {
        headers: reqHeaders,
      })
      setCors(res)
      res.set('content-type', 'text/html; charset=UTF-8')
      res.status(r.status)
      const buffer = Buffer.from(await r.arrayBuffer())
      res.end(buffer, 'binary')
    } else {
      setCors(res)
      res.end('no sessionId')
    }
  }

  res.end("No sessionId sent in query params");

})

// Intercepts a request to one of Qlik's REST APIs and proxies the request to
// Qlik Cloud.
app.get('/api/v1/*', async (req, res) => {
  const reqHeaders = {}
  if (req.headers['x-proxy-session-id']) {
    reqHeaders.cookie = tokenStore[req.headers['x-proxy-session-id']]?.qlikSession
  }

  const r = await fetch(`https://${qlikConfig.tenantUri}${req.path}`, {
    headers: reqHeaders,
  })
  setCors(res)
  res.status(r.status)
  const buffer = Buffer.from(await r.arrayBuffer())
  res.end(buffer, 'binary')
})

// fetch resourse from qlik using a redirect instead of proxy
// This endpoint is necessary when your web application uses the capability API.
app.get('/resources/*', async (req, res) => {
  setCors(res)
  res.redirect(`https://${qlikConfig.tenantUri}${req.path}`);
  res.end()
})

// Issues the necessary pre-flight request to make sure the browser
// knows how to work with the web application.
app.options('/*', async (req, res) => {
  setCors(res)
  res.status(200).end()
})

// Starts the server running this example.
const server = app.listen(3000, () => {
  console.log('Backend started')
})

// Websocket section for intercepting websocket requests from the
// frontend application. When the front end application communicates
// communicates with the backend using websockets, this set of
// functions will be invoked.
const wss = new WebSocketServer({ server })

wss.on('connection', async function connection(ws, req) {
  let isOpened = false
  const url = decodeURIComponent(req.url)
  const sessionId = url.match('sessionId=([0-9a-z]+)')[1]
  const appId = req.url.match('/app/(.*)\\?')[1]
  const cookie = tokenStore[sessionId]?.qlikSession
  const csrfToken = cookie.match('_csrfToken=(.*);')[1]
  const qlikWebSocket = new WebSocket(`wss://${qlikConfig.tenantUri}/app/${appId}/identity/preview?qlik-csrf-token=${csrfToken}`, {
    headers: {
      cookie,
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
