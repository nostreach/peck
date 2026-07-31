// Live clock
function tick() {
  const el = document.getElementById('clock')
  if (el) el.textContent = new Date().toLocaleTimeString()
}
tick()
setInterval(tick, 1000)

// Fetch /api/time
document.getElementById('btn-fetch')?.addEventListener('click', async () => {
  const pre = document.getElementById('fetch-result')
  pre.textContent = 'fetching...'
  try {
    const res = await fetch('./api/time')
    const data = await res.json()
    pre.textContent = JSON.stringify(data, null, 2)
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
