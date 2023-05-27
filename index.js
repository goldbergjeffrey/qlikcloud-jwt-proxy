import crypto from 'crypto'
import express from 'express'
import compression from 'compression'
import { generators } from 'openid-client'
import jsonwebtoken from 'jsonwebtoken'
import WebSocket, { WebSocketServer } from 'ws'

// jwt-idp key
const privateKey = process.env['privateKey'].replaceAll('\\n', '\n')

// idp config
const clientId = process.env['clientId']
const clientSecret = process.env['clientSecret']
const redirectUri = process.env['redirectUri']
const idpAuthorizeUri = `${process.env['idpUri']}/authorize`;
const idpTokenUri = `${process.env['idpUri']}/oauth/token`;
// qcs tenant
const tenantUri = process.env['tenantUri']

// local storage
const tokenStore = {}

const app = express()
app.use(compression({ threshold: 0 }))

app.get('/', (req, res) => {
  res.end('backend')
})

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
