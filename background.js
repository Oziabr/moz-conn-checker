const CONFIG = {
  testHost: 'example.org',
  dohEndpoint: 'https://mozilla.cloudflare-dns.com/dns-query',
  reachabilityTargets: [
    'https://www.mozilla.org/robots.txt',
    'https://www.cloudflare.com/robots.txt'
  ],
  stunServers: ['stun:stun.l.google.com:19302'],
  supabaseUrl: '',
  supabaseAnonKey: '',
  queueKey: 'pendingReports',
  uploadAlarm: 'upload-retry'
}

const ERROR_MAP = {
  NS_ERROR_UNKNOWN_HOST: 'this name could not be resolved, DNS lookups are being blocked or redirected',
  NS_ERROR_UNKNOWN_PROXY_HOST: 'the configured proxy could not be reached',
  NS_ERROR_CONNECTION_REFUSED: 'the connection was actively refused, likely a firewall rule or closed port',
  NS_ERROR_PROXY_CONNECTION_REFUSED: 'a proxy on this network refused the connection',
  NS_ERROR_NET_TIMEOUT: 'the connection timed out with no response, traffic is likely being silently dropped',
  NS_ERROR_NET_RESET: 'the connection was reset mid stream, a sign of active interference rather than a closed port',
  NS_ERROR_NET_INTERRUPT: 'the connection was interrupted before completing',
  NS_ERROR_OFFLINE: 'this device reports no network connection at all'
}

const classifyError = code => {
  if (ERROR_MAP[code]) return ERROR_MAP[code]
  if (code.startsWith('NS_ERROR_SEC_') || code.startsWith('SSL_ERROR_') || code.startsWith('SEC_ERROR_')) return 'a TLS or certificate error occurred, possibly an intercepting proxy or captive portal'
  return `unrecognised network error (${code})`
}

const probeUrl = (url, timeoutMs) => new Promise(resolve => {
  let settled = false
  const finish = result => {
    if (settled) return
    settled = true
    browser.webRequest.onErrorOccurred.removeListener(onError)
    resolve(result)
  }
  const onError = details => finish({ ok: false, code: details.error, detail: classifyError(details.error) })
  browser.webRequest.onErrorOccurred.addListener(onError, { urls: [url] })
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  fetch(url, { signal: controller.signal, cache: 'no-store' })
    .then(res => finish({ ok: true, status: res.status }))
    .catch(() => finish({ ok: false, code: 'CLIENT_TIMEOUT', detail: 'no response within the timeout window, traffic is likely being silently dropped' }))
    .finally(() => clearTimeout(timer))
})

const checkDns = async () => {
  const direct = await probeUrl(`https://${CONFIG.testHost}/`, 4000)
  if (direct.ok) return { id: 'dns', label: 'DNS resolution', status: 'ok', detail: 'system DNS resolves and reaches the test host' }
  const dohRes = await fetch(`${CONFIG.dohEndpoint}?name=${CONFIG.testHost}&type=A`, { headers: { accept: 'application/dns-json' } }).catch(() => null)
  const dohBody = dohRes && dohRes.ok ? await dohRes.json() : null
  const dohResolved = dohBody && dohBody.Answer && dohBody.Answer.length > 0
  if (direct.code === 'NS_ERROR_UNKNOWN_HOST' && dohResolved) {
    return { id: 'dns', label: 'DNS resolution', status: 'fail', detail: 'the name exists on the public internet but this network refuses to resolve it locally, DNS is being blocked or filtered' }
  }
  return { id: 'dns', label: 'DNS resolution', status: 'warn', detail: direct.detail }
}

const checkReachability = async () => {
  const results = await Promise.all(CONFIG.reachabilityTargets.map(url => probeUrl(url, 5000)))
  const failures = results.filter(r => !r.ok)
  if (failures.length === 0) return { id: 'tcp443', label: 'HTTPS reachability', status: 'ok', detail: 'standard web traffic on port 443 reaches the internet' }
  if (failures.length === results.length) return { id: 'tcp443', label: 'HTTPS reachability', status: 'fail', detail: failures[0].detail }
  return { id: 'tcp443', label: 'HTTPS reachability', status: 'warn', detail: 'some HTTPS destinations are unreachable while others work, the filtering looks destination specific' }
}

const checkProxy = async () => {
  const settings = await browser.proxy.settings.get({})
  const value = settings && settings.value
  const usesProxy = value && value.proxyType && value.proxyType !== 'none'
  return {
    id: 'proxy',
    label: 'Proxy configuration',
    status: usesProxy ? 'warn' : 'ok',
    detail: usesProxy ? `traffic is routed through a configured proxy (${value.proxyType}), that proxy can apply its own filtering` : 'no system proxy is configured'
  }
}

const checkUdp = () => new Promise(resolve => {
  const pc = new RTCPeerConnection({ iceServers: CONFIG.stunServers.map(urls => ({ urls })) })
  let found = false
  pc.onicecandidate = event => {
    if (event.candidate && event.candidate.protocol === 'udp') found = true
  }
  const finish = () => {
    pc.close()
    resolve(found
      ? { id: 'udp', label: 'UDP reachability', status: 'ok', detail: 'outbound UDP is allowed, most VPN protocols should at least attempt a connection' }
      : { id: 'udp', label: 'UDP reachability', status: 'fail', detail: 'no UDP candidates were gathered, outbound UDP looks blocked, this breaks WireGuard and most VPN protocols' })
  }
  setTimeout(finish, 4000)
  pc.createDataChannel('probe')
  pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(finish)
})

const CHECKS = [checkDns, checkReachability, checkUdp, checkProxy]

const runDiagnostics = async () => {
  const results = await Promise.all(CHECKS.map(check => check()))
  return { timestamp: new Date().toISOString(), results }
}

const queueReport = async report => {
  const stored = await browser.storage.local.get(CONFIG.queueKey)
  const queue = stored[CONFIG.queueKey] || []
  queue.push(report)
  await browser.storage.local.set({ [CONFIG.queueKey]: queue })
}

const uploadQueue = async () => {
  if (!CONFIG.supabaseUrl || !CONFIG.supabaseAnonKey) return
  const stored = await browser.storage.local.get(CONFIG.queueKey)
  const queue = stored[CONFIG.queueKey] || []
  if (queue.length === 0) return
  const res = await fetch(`${CONFIG.supabaseUrl}/rest/v1/reports`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      apikey: CONFIG.supabaseAnonKey,
      authorization: `Bearer ${CONFIG.supabaseAnonKey}`,
      prefer: 'return=minimal'
    },
    body: JSON.stringify(queue.map(r => ({ client_timestamp: r.timestamp, results: r.results })))
  }).catch(() => null)
  if (res && res.ok) await browser.storage.local.set({ [CONFIG.queueKey]: [] })
}

browser.alarms.create(CONFIG.uploadAlarm, { periodInMinutes: 5 })
browser.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === CONFIG.uploadAlarm) uploadQueue()
})

browser.runtime.onMessage.addListener(async message => {
  if (message.type !== 'RUN_DIAGNOSTICS') return
  const report = await runDiagnostics()
  await queueReport(report)
  return report
})
