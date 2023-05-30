let sessionId = null

self.addEventListener('fetch', function(event) {
  if (
    sessionId !== null &&
    event.request.method === 'GET' &&
    event.request.url.startsWith('https://jwt-proxy-combined.qlik.repl.co/api/v1')
  ) {
    event.respondWith(
      (async () => {
        console.log('fetch', event.request.url)
        console.log(sessionId)
        const newHeaders = new Headers(event.request.headers)
        newHeaders.set('x-proxy-session-id', sessionId)
        newHeaders.set('sec-fetch-mode', 'cors')
        const newRequest = new Request(event.request, {
          headers: newHeaders,
          mode: 'cors',
        })
        return fetch(newRequest)
      })()
    )
  }
  if (
    sessionId !== null &&
    e?.data?.type === 'single'
  ) {
    event.respondWith(
      (async () => {
        console.log('fetch', event.request.url)
        console.log(sessionId)
        const newHeaders = new Headers(event.request.headers)
        newHeaders.set('x-proxy-session-id', sessionId)
        newHeaders.set('sec-fetch-mode', 'cors')
        const newRequest = new Request(event.request, {
          headers: newHeaders,
          mode: 'cors',
        })
        return fetch(newRequest)
      })()
    )
  }
})

self.addEventListener('install', function(e) {
  console.log('service worker has been installed')
})
self.addEventListener('activate', function(e) {
  console.log('service worker has been activated')
})

self.addEventListener('message', function(e) {
  if (e.data?.type === 'setProxyHeader') {
    console.log('session has been set')
    sessionId = e.data.sessionId
  }
})
