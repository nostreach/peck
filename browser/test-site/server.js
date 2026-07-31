/**
 * peck tunnel test site — static file server with dynamic endpoints
 *
 * Serves the test-site/ directory on localhost:8080.
 * Dynamic routes: /api/time (JSON), /submit (form handler), /redirect (302)
 *
 * Usage: node examples/test-site/server.js
 */
import { createServer } from 'http'
import { readFile } from 'fs/promises'
import { extname, join, normalize } from 'path'
import { fileURLToPath, pathToFileURL } from 'url'

const PORT = parseInt(process.env.PORT || '8081', 10)
const ROOT = fileURLToPath(new URL('.', import.meta.url))

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
}

// Route clean URLs to .html files
function resolvePath(urlPath) {
  // Remove query string
  const path = urlPath.split('?')[0]

  // Dynamic routes
  if (path === '/api/time') return { dynamic: 'api/time' }
  if (path === '/submit') return { dynamic: 'submit' }
  if (path === '/redirect') return { dynamic: 'redirect' }

  // Clean URL → .html file
  let filePath = path
  if (path === '/' || path === '') filePath = '/index.html'
  else if (!extname(path)) filePath = path + '.html'

  // Security: normalize and prevent path traversal
  const resolved = normalize(join(ROOT, filePath))
  if (!resolved.startsWith(ROOT)) return { dynamic: '403' }

  return { file: resolved }
}

const server = createServer(async (req, res) => {
  const method = req.method
  const route = resolvePath(req.url)

  // ── Dynamic routes ──────────────────────────────────

  if (route.dynamic === 'api/time') {
    const data = JSON.stringify({
      time: new Date().toISOString(),
      epoch: Date.now(),
      server: 'peck-test-site'
    })
    res.writeHead(200, { 'Content-Type': MIME['.json'] })
    res.end(data)
    return
  }

  if (route.dynamic === 'redirect') {
    res.writeHead(302, { Location: '/' })
    res.end()
    return
  }

  if (route.dynamic === 'submit') {
    let body = ''
    for await (const chunk of req) body += chunk

    let params = {}
    if (method === 'POST') {
      // Parse URL-encoded body
      for (const pair of body.split('&')) {
        const [k, v] = pair.split('=').map(decodeURIComponent)
        if (k) params[k] = (v || '').replace(/\+/g, ' ')
      }
    } else {
      // GET — parse query string
      const qs = req.url.split('?')[1] || ''
      for (const pair of qs.split('&')) {
        const [k, v] = pair.split('=').map(decodeURIComponent)
        if (k) params[k] = (v || '').replace(/\+/g, ' ')
      }
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0d1117">
<title>Submit · peck</title>
<link rel="stylesheet" href="./assets/style.css"></head>
<body>
<div class="container">
<header class="hero">
  <img src="./assets/logo.svg" alt="peck" class="hero-logo">
  <h1>result</h1>
  <p>Your ${method} submission came through the tunnel.</p>
</header>
<nav>
  <a href="./">Home</a><a href="./about">About</a><a href="./links">Links</a>
  <a href="./form">Form</a><a href="./redirect">Redirect</a><a href="./missing">404</a>
</nav>
<main>
  <section class="card">
    <h2>Form result (${method})</h2>
    <p style="color: var(--success)">✅ ${method} request received through tunnel</p>
    <pre>${JSON.stringify(params, null, 2)}</pre>
    <p style="margin-top: 16px"><a href="./form">← Back to form</a></p>
  </section>
</main>
<footer><p>Served through <strong>peck</strong> — Nostr-signaled WebRTC tunnel</p></footer>
</div>
</body></html>`
    res.writeHead(200, { 'Content-Type': MIME['.html'] })
    res.end(html)
    return
  }

  if (route.dynamic === '403') {
    res.writeHead(403, { 'Content-Type': MIME['.html'] })
    res.end('<h1>403 Forbidden</h1>')
    return
  }

  // ── Static files ────────────────────────────────────

  try {
    const data = await readFile(route.file)
    const ext = extname(route.file)
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' })
    res.end(data)
  } catch {
    // Custom 404
    const notFound = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0d1117">
<title>404 · peck</title>
<link rel="stylesheet" href="./assets/style.css"></head>
<body>
<div class="container">
<header class="hero">
  <img src="./assets/logo.svg" alt="peck" class="hero-logo">
  <h1>404</h1>
  <p>Not found — but the tunnel delivered this error correctly.</p>
</header>
<nav>
  <a href="./">Home</a><a href="./about">About</a><a href="./links">Links</a>
  <a href="./form">Form</a><a href="./redirect">Redirect</a><a href="./missing">404</a>
</nav>
<main>
  <section class="card">
    <h2>404 — not found</h2>
    <p>The path <code>${req.url.split('?')[0]}</code> was not found on this server.</p>
    <p style="margin-top: 12px; color: var(--text-muted)">But the good news is: the tunnel delivered this error page correctly. ✅</p>
    <p style="margin-top: 16px"><a href="./">← Go home</a></p>
  </section>
</main>
<footer><p>Served through <strong>peck</strong> — Nostr-signaled WebRTC tunnel</p></footer>
</div>
</body></html>`
    res.writeHead(404, { 'Content-Type': MIME['.html'] })
    res.end(notFound)
  }
})

server.listen(PORT, () => {
  console.log(`peck test site running on http://localhost:${PORT}`)
})
