/**
 * peck tunnel test site — static file server with dynamic endpoints
 *
 * Serves the test-site/ directory on the port from PORT (default 8081).
 * Dynamic routes: /api/time (JSON), /submit (form handler), /redirect (302)
 *
 * Usage: node examples/test-site/server.js
 */
import { createServer } from 'http'
import { readFile } from 'fs/promises'
import { extname, join, normalize } from 'path'
import { fileURLToPath } from 'url'

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

// ── Helpers ─────────────────────────────────────────

// Safe percent-decoding: never throws on malformed input like '%ZZ'
function safeDecode(s) {
  try { return decodeURIComponent(s) } catch { return s }
}

// Minimal query/body parser: urlencoded (+ as space), malformed-safe
function parseParams(raw) {
  const params = {}
  for (const pair of raw.split('&')) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    const k = eq === -1 ? pair : pair.slice(0, eq)
    const v = eq === -1 ? '' : pair.slice(eq + 1)
    const key = safeDecode(k.replace(/\+/g, ' ')).trim()
    if (key) params[key] = safeDecode(v.replace(/\+/g, ' '))
  }
  return params
}

// HTML-escape for anything reflected into a page
function esc(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
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

// Shared Amber-Terminal page shell for JS-rendered pages (submit, 404)
// Uses class-based styling only — survives the peck client's CSS rewriter.
function page({ title, headline, headlineAccent, current, body }) {
  const nav = [
    ['./', 'home'],
    ['./about', 'about'],
    ['./links', 'links'],
    ['./form', 'form'],
    ['./redirect', 'redirect'],
    ['./missing', '404'],
  ]
    .map(([href, label]) => {
      const cur = label === current ? ' aria-current="page"' : ''
      return `<a class="nav-link" href="${href}"${cur}>${label}</a>`
    })
    .join('\n      ')

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0a0908">
<title>${esc(title)} · peck</title>
<link rel="icon" href="./assets/logo.svg" type="image/svg+xml">
<link rel="stylesheet" href="./assets/style.css">
</head>
<body>
<div class="wrap">

  <div class="sysbar">
    <span><b class="sys-key">peck</b> · tunnel test site</span>
    <span>every byte on this page crossed the <span class="st">p2p datachannel</span></span>
  </div>

  <header class="hero">
    <img src="./assets/logo.svg" alt="peck" class="hero-logo">
    <div class="logo">peck<span class="cursor"></span></div>
    <h1 class="hero-title">${esc(headline)} <em class="accent">${esc(headlineAccent)}</em></h1>
  </header>

  <nav class="mainnav" aria-label="Test pages">
      ${nav}
  </nav>

  <main class="main-area">
${body}
  </main>

  <footer class="statusline">
    <span><span class="dot">●</span> peck://tunnel · p2p · e2e encrypted</span>
    <span><a class="foot-link" href="https://github.com/nostreach/peck">github.com/nostreach/peck</a></span>
  </footer>

</div>
</body>
</html>`
}

// ── Server ─────────────────────────────────────────

const server = createServer(async (req, res) => {
  const method = req.method
  const route = resolvePath(req.url)

  // ── Dynamic routes ──────────────────────────────

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
      params = parseParams(body)
    } else {
      const qs = req.url.split('?')[1] || ''
      params = parseParams(qs)
    }

    const html = page({
      title: 'Submit',
      headline: 'form',
      headlineAccent: 'result',
      current: 'form',
      body: `    <section class="card">
      <h2>${esc(method.toLowerCase())} submission</h2>
      <p>Your ${esc(method)} request came through the tunnel and was answered.</p>
      <pre class="term">${esc(JSON.stringify(params, null, 2))}</pre>
      <p><a class="btn" href="./form">← back to form</a></p>
    </section>`
    })
    res.writeHead(200, { 'Content-Type': MIME['.html'] })
    res.end(html)
    return
  }

  if (route.dynamic === '403') {
    res.writeHead(403, { 'Content-Type': MIME['.html'] })
    res.end('<h1>403 Forbidden</h1>')
    return
  }

  // ── Static files ────────────────────────────────

  try {
    const data = await readFile(route.file)
    const ext = extname(route.file)
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' })
    res.end(data)
  } catch {
    // Custom 404
    const notFound = page({
      title: '404',
      headline: 'error',
      headlineAccent: '404',
      current: '404',
      body: `    <section class="card">
      <h2>not found</h2>
      <p>The path <code>${esc(req.url.split('?')[0])}</code> was not found on this server.</p>
      <p>The good news: the tunnel delivered this error page correctly.</p>
      <p><a class="btn" href="./">← go home</a></p>
    </section>`
    })
    res.writeHead(404, { 'Content-Type': MIME['.html'] })
    res.end(notFound)
  }
})

server.listen(PORT, () => {
  console.log(`peck test site running on http://localhost:${PORT}`)
})
