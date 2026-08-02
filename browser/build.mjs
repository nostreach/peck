/**
 * peck build script — bundles browser client into a single self-contained file.
 *
 * Before: client.html loads @noble/* and @trystero-p2p/core from cdn.jsdelivr.net
 * After:  everything is inlined into dist/client.bundle.js — zero external requests
 *
 * Usage: npm run build
 * Output: dist/client.bundle.js + dist/client.html + dist/sw.js
 */

import { build } from 'esbuild'
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'fs'

mkdirSync('dist', { recursive: true })

// ─── 1. Bundle client.js + all deps into a single ESM file ───

await build({
  entryPoints: ['src/client.js'],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  outfile: 'dist/client.bundle.js',
  target: ['es2020'],
  minify: true,
  sourcemap: false,
  legalComments: 'none',
  // werift is a Node.js-only WebRTC polyfill (dynamically imported by
  // transport.js for server-side use). The browser has native WebRTC.
  // Marking it external prevents esbuild from trying to bundle werift's
  // Node.js deps (dgram, net, crypto, etc.).
  external: ['werift'],
  logLevel: 'info',
})

// ─── 1b. Copy wg-country-codes.js + geoip-data.js to dist/ ───
// These are NOT bundled — wg-country-codes.js has no deps, and geoip-data.js
// (~10MB) MUST stay as a separate file so it loads lazily via dynamic import().
// Lazy loading is critical: a static/eager load of 10MB blocks page init.

let wgcc = readFileSync('src/wg-country-codes.js', 'utf8')
// Fix the lazy import path: './geoip-data.js' → '/geoip-data.js' for dist
wgcc = wgcc.replace("import('./geoip-data.js')", "import('/geoip-data.js')")
writeFileSync('dist/wg-country-codes.js', wgcc)
copyFileSync('src/geoip-data.js', 'dist/geoip-data.js')

// ─── 2. Generate dist/client.html (no importmap, loads local bundle) ───

let html = readFileSync('examples/client.html', 'utf8')

// Remove the entire importmap block
html = html.replace(/<script type="importmap">[\s\S]*?<\/script>\s*/, '')

// Replace the CDN import with local bundle import.
// Spec 029: use absolute path '/client.bundle.js' (not './') so the
// import resolves correctly when the page is served under a URL path
// prefix like /_p8082/. A relative './client.bundle.js' would resolve
// to /_p8082/client.bundle.js and 404.
html = html.replace(
  /import \{ connect, formatDiagnostics, generateKeypair, deriveNpub \} from '\.\.\/src\/client\.js\?v=[\w\d]+'/,
  "import { connect, formatDiagnostics, generateKeypair, deriveNpub } from '/client.bundle.js'"
)

// Fallback: also handle import without version query
html = html.replace(
  /import \{ connect, formatDiagnostics, generateKeypair, deriveNpub \} from '\.\.\/src\/client\.js'/,
  "import { connect, formatDiagnostics, generateKeypair, deriveNpub } from '/client.bundle.js'"
)

// Remove the NativeTransport import lines (comment + import), but NOT the
// wg-country-codes import that sits between the NativeTransport import and
// the window.NativeTransport line.
// The old regex used [\s\S]*? which ate the wg-country-codes import too —
// that was the root cause of flags (❓) being broken in production.
html = html.replace(
  /\/\/ NativeTransport is the default[^\n]*\n\s*\/\/ We import it[^\n]*\n\s*import \{ NativeTransport[^}]*\} from '[^']+'\n/,
  ''
)

// Replace wg-country-codes.js import path for dist
html = html.replace(
  /import \{ lookupCountry, ccToFlag, getCachedCountry, _whenGeoipReady \} from '[^']+'/,
  "import { lookupCountry, ccToFlag, getCachedCountry, _whenGeoipReady } from '/wg-country-codes.js'"
)

// Remove the window.NativeTransport exposure line (and its comment)
html = html.replace(/\s*\/\/ Expose for debugging\n\s*window\.NativeTransport\s*=\s*NativeTransport[^\n]*\n/, '\n')

writeFileSync('dist/client.html', html)

// ─── 3. Copy sw.js as-is ───

copyFileSync('examples/sw.js', 'dist/sw.js')

// ─── 4. Report bundle size ───

const bundleSize = readFileSync('dist/client.bundle.js').length
const sizeKB = (bundleSize / 1024).toFixed(1)
console.log(`\n✅ Build complete`)
console.log(`   client.bundle.js: ${sizeKB} KB (${(bundleSize / 1024 / (bundleSize > 100*1024 ? 3 : 1)).toFixed(1)} KB ${bundleSize > 100*1024 ? 'estimated gz' : ''})`)
console.log(`   client.html: ${(html.length / 1024).toFixed(1)} KB`)
console.log(`   sw.js copied`)
console.log(`\\n   Deploy: scp dist/* → /var/www/peck/`)
