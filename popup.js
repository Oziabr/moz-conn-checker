const HINTS = {
  'dns-fail': 'try switching this device to a different DNS server, or use DNS over HTTPS in your VPN client',
  'dns-warn': 'try a different DNS server before assuming the destination itself is down',
  'tcp443-fail': 'this network is blocking general web traffic, ask whoever runs the access point about content filtering',
  'tcp443-warn': 'the destination you need may be specifically blocked, try a different server or provider',
  'udp-fail': 'pick a VPN protocol that runs over TCP on port 443 instead of UDP',
  'proxy-warn': 'ask your network administrator whether that proxy filters the protocols you need'
}

const button = document.getElementById('run')
const output = document.getElementById('output')

const renderItem = item => {
  const hint = HINTS[`${item.id}-${item.status}`]
  const li = document.createElement('li')
  li.className = item.status
  li.innerHTML = `
    <div class="label"><span class="dot"></span>${item.label}</div>
    <p class="detail">${item.detail}</p>
    ${hint ? `<p class="detail">Next step: ${hint}</p>` : ''}
  `
  return li
}

const render = report => {
  const list = document.createElement('ul')
  report.results.map(renderItem).forEach(li => list.appendChild(li))
  output.innerHTML = ''
  output.appendChild(list)
}

button.addEventListener('click', async () => {
  button.disabled = true
  button.textContent = 'Checking...'
  const report = await browser.runtime.sendMessage({ type: 'RUN_DIAGNOSTICS' })
  render(report)
  button.disabled = false
  button.textContent = 'Run check'
})
