import crypto from 'crypto'
import express from 'express'
import compression from 'compression'
import { generators } from 'openid-client'
import jsonwebtoken from 'jsonwebtoken'
import WebSocket, { WebSocketServer } from 'ws'

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

// This example uses express.js to provide the proxy services between the
// frontend web application and Qlik Cloud REST endpoints and websocket
// connections to the engine.
const app = express()
app.use(compression({ threshold: 0 }))

app.get('/', (req, res) => {
  res.end('backend')
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
  const { code, error, state } = req.query;
  //If the user is not authenticated to this example, do the dance.
  if (error === 'login_required' || error === 'interaction_required') {
    res.redirect(401, "/login");
    res.end();
    return;
  }

  if (!tokenStore[state]) {
    console.log('state does not exist')
    res.status(401).end()
  }

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
    const qlikSession = await jwtLogin(idToken.email, idToken.name, idToken.sub)

    const frontendSession = crypto.randomBytes(16).toString('hex')
    console.log(frontendSession)
    tokenStore[frontendSession] = { idpToken, qlikSession }
    res.redirect(`https://frontend5wirelessopengl--hvm.repl.co/?sessionId=${frontendSession}&name=${idToken.name}`)
  } else {
    console.log(await idpTokenRes.text())
  }

  res.end()
})


app.get('/single/*', async (req, res) => {
  const path = req.originalUrl
  const reqHeaders = {}
  if (req.headers['x-proxy-session-id']) {
    reqHeaders.cookie = tokenStore[req.headers['x-proxy-session-id']]?.qlikSession
    const r = await fetch(`https://${tenantUri}${path}`, {
      headers: reqHeaders,
    })
    setCors(res)
    res.status(r.status)
    const buffer = Buffer.from(await r.arrayBuffer())
    res.end(buffer, 'binary')
  } else {
    setCors(res)
    res.end('no sessionId')
  }

})

app.get('/api/v1/*', async (req, res) => {
  const reqHeaders = {}
  if (req.headers['x-proxy-session-id']) {
    reqHeaders.cookie = tokenStore[req.headers['x-proxy-session-id']]?.qlikSession
  }

  const r = await fetch(`https://${tenantUri}${req.path}`, {
    headers: reqHeaders,
  })
  setCors(res)
  res.status(r.status)
  const buffer = Buffer.from(await r.arrayBuffer())
  res.end(buffer, 'binary')
})

// const cachedResourse = new Map()
// app.get('/resources/*', async (req, res) => {
//   setCors(res)
//   const cache = cachedResourse.get(req.path)
//   if (cache) {
//     res.set('content-type', cache.contentType)
//     res.status(cache.status)
//     res.end(cache.buffer, 'binary')
//     return
//   }
//   const r = await fetch(`https://${tenantUri}${req.path}`, {
//     headers: {
//       'accept-encoding': 'deflate, gzip',
//     }
//   })
//   res.set('content-type', r.headers.get('content-type'))
//   res.status(r.status)
//   const buffer = Buffer.from(await r.arrayBuffer())
//   res.end(buffer, 'binary')
//   cachedResourse.set(req.path, { buffer, status: r.status, contentType: r.headers.get('content-type') })
// })

// fetch resourse from qlik using a redirect instead of proxy
// replit is slow and resourse-limited :(
app.get('/resources/*', async (req, res) => {
  setCors(res)
  res.redirect(`https://${tenantUri}${req.path}`);
  res.end()
})

app.options('/*', async (req, res) => {
  setCors(res)
  res.status(200).end()
})

const server = app.listen(3000, () => {
  console.log('Backend started')
})

const wss = new WebSocketServer({ server })

wss.on('connection', async function connection(ws, req) {
  let isOpened = false
  const sessionId = req.url.match('sessionId=(.*)')[1]
  const appId = req.url.match('/app/(.*)\\?')[1]
  const cookie = tokenStore[sessionId]?.qlikSession

  const csrfToken = cookie.match('_csrfToken=(.*);')[1]
  const qlikClinetWebSocket = new WebSocket(`wss://${tenantUri}/app/${appId}/identity/preview?qlik-csrf-token=${csrfToken}`, {
    headers: {
      cookie,
    },
  })

  qlikClinetWebSocket.on('error', console.error)
  const openPromise = new Promise((resolve) => {
    qlikClinetWebSocket.on('open', function open() {
      resolve()
    })
  })

  ws.on('message', async function message(data) {
    if (!isOpened) {
      await openPromise
      isOpened = true
    }
    qlikClinetWebSocket.send(data.toString())
  })

  qlikClinetWebSocket.on('message', function message(data) {
    ws.send(data.toString())
  })
})

function setCors(res) {
  res.set('Access-Control-Allow-Origin', 'https://frontend5wirelessopengl--hvm.repl.co')
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.set('Access-Control-Allow-Headers', 'Content-Type, x-proxy-session-id')
  res.set('Access-Control-Allow-Credentials', 'true')
}

async function jwtLogin(email, name, originalSub) {
  const signingOptions = {
    keyid: '6d08d051-cef3-443b-bea4-c787f776f9f3',
    algorithm: 'RS256',
    issuer: 'mo753olytor0ylg.eu.qlik-stage.com',
    expiresIn: '1m',
    audience: 'qlik.api/login/jwt-session',
    notBefore: '0s',
  }

  const payload = {
    jti: crypto.randomBytes(16).toString('hex'),
    sub: `BackendApp|${originalSub}`,
    subType: 'user',
    email_verified: true,
    email,
    name,
  }

  const token = jsonwebtoken.sign(payload, privateKey, signingOptions)

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
