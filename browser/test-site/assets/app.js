// peck test-site — page scripts
// Clock, fetch probe, large-content generator.

// Live clock — proves JS executes through the tunnel
function tick() {
  const el = document.getElementById('clock')
  if (el) el.textContent = new Date().toLocaleTimeString()
}
tick()
setInterval(tick, 1000)

// Fetch test — HTTP request through the tunnel
document.getElementById('btn-fetch')?.addEventListener('click', async () => {
  const pre = document.getElementById('fetch-result')
  pre.textContent = 'fetching ./api/time ...'
  try {
    const t0 = performance.now()
    const res = await fetch('./api/time')
    const data = await res.json()
    const ms = Math.round(performance.now() - t0)
    pre.textContent =
      `GET ./api/time → ${res.status} ${res.statusText || 'OK'} (${ms} ms)\n` +
      JSON.stringify(data, null, 2)
  } catch (err) {
    pre.textContent = 'Error: ' + err.message
  }
})

// Lorem ipsum generator for large content test
// Guard against double-execution (peck re-runs scripts on back-navigation)
const lorem = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.'
const container = document.getElementById('lorem')
if (container && !container.dataset.filled) {
  container.dataset.filled = '1'
  for (let i = 0; i < 100; i++) {
    const p = document.createElement('p')
    p.textContent = `[${i + 1}] ${lorem}`
    container.appendChild(p)
  }
}
