#Requires -Version 5.1
<#
.SYNOPSIS
  Sequential network diagnostics for non-technical users.
  Run as a regular user (no elevation needed except for raw ICMP MTU on some Windows versions).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ─── config ──────────────────────────────────────────────────────────────────

$DOH_URL        = 'https://mozilla.cloudflare-dns.com/dns-query'
$TEST_HOST      = 'example.org'
$HTTPS_TARGETS  = @('https://www.mozilla.org/robots.txt', 'https://www.cloudflare.com/robots.txt')
$STUN_HOST      = 'stun.l.google.com'
$STUN_PORT      = 19302
$TRACE_TARGET   = '1.1.1.1'
$MTU_TARGET     = '1.1.1.1'
$MTU_MAX        = 1500
$MTU_MIN        = 576
$MTU_TIMEOUT_MS = 1000

$VPN_PORTS = @(
  [pscustomobject]@{ Port = 1194; Proto = 'UDP'; Label = 'OpenVPN UDP' }
  [pscustomobject]@{ Port = 1194; Proto = 'TCP'; Label = 'OpenVPN TCP' }
  [pscustomobject]@{ Port = 51820; Proto = 'UDP'; Label = 'WireGuard'  }
  [pscustomobject]@{ Port = 500;   Proto = 'UDP'; Label = 'IKEv2/IPsec' }
  [pscustomobject]@{ Port = 4500;  Proto = 'UDP'; Label = 'IKEv2 NAT-T' }
  [pscustomobject]@{ Port = 1723;  Proto = 'TCP'; Label = 'PPTP (legacy)' }
  [pscustomobject]@{ Port = 443;   Proto = 'TCP'; Label = 'SSL VPN / HTTPS' }
)

# overhead added by each VPN encapsulation, used to judge a discovered MTU
$VPN_OVERHEAD = @{
  'WireGuard'    = 60
  'OpenVPN UDP'  = 70
  'OpenVPN TCP'  = 72
  'IKEv2/IPsec'  = 85
}

# ─── output helpers ──────────────────────────────────────────────────────────

function Write-Header ([string]$text) {
  Write-Host "`n━━  $text  " -ForegroundColor Cyan
}

function Write-Ok    ([string]$msg) { Write-Host "  ✓  $msg" -ForegroundColor Green }
function Write-Warn  ([string]$msg) { Write-Host "  ▲  $msg" -ForegroundColor Yellow }
function Write-Fail  ([string]$msg) { Write-Host "  ✗  $msg" -ForegroundColor Red }
function Write-Info  ([string]$msg) { Write-Host "     $msg" -ForegroundColor Gray }
function Write-Hint  ([string]$msg) { Write-Host "  →  $msg" -ForegroundColor White }

# ─── check 1: dns ────────────────────────────────────────────────────────────

function Test-Dns {
  Write-Header 'DNS resolution'

  $sysResult = Resolve-DnsName -Name $TEST_HOST -Type A -ErrorAction SilentlyContinue
  $sysOk = $null -ne $sysResult

  $dohResult = Invoke-RestMethod `
    -Uri "${DOH_URL}?name=${TEST_HOST}&type=A" `
    -Headers @{ Accept = 'application/dns-json' } `
    -ErrorAction SilentlyContinue
  $dohOk = $null -ne $dohResult -and $dohResult.Answer.Count -gt 0

  if ($sysOk -and $dohOk) {
    Write-Ok "System DNS resolves $TEST_HOST  →  $($sysResult[0].IPAddress)"
    return
  }

  if (-not $sysOk -and $dohOk) {
    Write-Fail "System DNS fails to resolve $TEST_HOST but DNS-over-HTTPS succeeds"
    Write-Info  "The name exists on the public internet but this network is blocking or filtering local DNS"
    Write-Hint  "Switch to an encrypted DNS resolver in your OS settings, or configure DoH in Firefox/your VPN client"
    return
  }

  if (-not $sysOk -and -not $dohOk) {
    Write-Fail "Both system DNS and DNS-over-HTTPS fail for $TEST_HOST"
    Write-Hint  "This usually means there is no internet connectivity at all, or all outbound DNS (port 53 and 443) is being blocked"
    return
  }

  Write-Warn "System DNS resolves but DoH check failed (DoH endpoint itself may be blocked)"
  Write-Hint  "If your VPN relies on DoH for leak prevention it may not work on this network"
}

# ─── check 2: https reachability ─────────────────────────────────────────────

function Test-HttpsReachability {
  Write-Header 'HTTPS reachability (TCP 443)'

  $results = $HTTPS_TARGETS | ForEach-Object {
    $url = $_
    try {
      $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
      [pscustomobject]@{ Url = $url; Ok = $true; Code = $resp.StatusCode }
    } catch {
      $code = $_.Exception.Response.StatusCode.value__
      $msg  = $_.Exception.Message
      [pscustomobject]@{ Url = $url; Ok = $false; Code = $code; Msg = $msg }
    }
  }

  $failed = @($results | Where-Object { -not $_.Ok })

  if ($failed.Count -eq 0) {
    Write-Ok "All HTTPS targets reachable"
    return
  }

  if ($failed.Count -eq $results.Count) {
    Write-Fail "All HTTPS targets unreachable"
    Write-Hint  "Standard web traffic on port 443 is being blocked — check for a captive portal, aggressive proxy, or content filter"
    return
  }

  $failed | ForEach-Object { Write-Warn "Unreachable: $($_.Url)  ($($_.Msg))" }
  Write-Hint "Some HTTPS destinations work while others don't — the filtering appears destination-specific (domain or IP block)"
}

# ─── check 3: proxy detection ────────────────────────────────────────────────

function Test-ProxyConfig {
  Write-Header 'Proxy configuration'

  $found = $false

  # WinHTTP (used by many system and VPN clients)
  $winhttp = netsh winhttp show proxy 2>$null
  if ($winhttp -match 'Proxy Server\(s\)\s*:\s*(.+)') {
    Write-Warn "WinHTTP proxy configured: $($Matches[1].Trim())"
    Write-Info  "System services and some VPN clients route through this proxy"
    $found = $true
  }

  # IE/WinINET proxy (used by most browsers when no per-app override)
  $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  $ieProxy = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
  if ($ieProxy.ProxyEnable -eq 1 -and $ieProxy.ProxyServer) {
    Write-Warn "Browser/WinINET proxy configured: $($ieProxy.ProxyServer)"
    Write-Info  "Firefox and most browsers use this unless overridden in their own settings"
    $found = $true
  }
  if ($ieProxy.AutoConfigURL) {
    Write-Warn "PAC / auto-config URL set: $($ieProxy.AutoConfigURL)"
    Write-Info  "A PAC script is selecting which traffic goes through a proxy — the script itself may apply filtering logic"
    $found = $true
  }

  # environment variables (picked up by curl, Python, Node.js, many CLI tools)
  $envProxy = @($env:HTTP_PROXY, $env:HTTPS_PROXY, $env:ALL_PROXY) | Where-Object { $_ }
  if ($envProxy.Count -gt 0) {
    Write-Warn "Environment proxy variables set: $($envProxy -join ', ')"
    Write-Info  "CLI tools and many apps inherit these — they follow the proxy even when browser settings are cleared"
    $found = $true
  }

  if (-not $found) {
    Write-Ok "No proxy configuration found in WinHTTP, WinINET, or environment"
  } else {
    Write-Hint "Any configured proxy can apply its own filtering independently of what the AP or router does"
  }
}

# ─── check 4: udp (stun probe) ───────────────────────────────────────────────

function Test-UdpStun {
  Write-Header 'Outbound UDP (STUN probe)'

  # STUN Binding Request — 20 bytes, magic cookie, random transaction ID
  $stunRequest = [byte[]](
    0x00, 0x01,             # message type: Binding Request
    0x00, 0x00,             # message length: 0 attributes
    0x21, 0x12, 0xa4, 0x42  # magic cookie
  ) + [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(12)

  $udp = [System.Net.Sockets.UdpClient]::new()
  $udp.Client.ReceiveTimeout = 2000

  try {
    $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $udp.Send($stunRequest, $stunRequest.Length, $STUN_HOST, $STUN_PORT) | Out-Null
    $response = $udp.Receive([ref]$ep)
    if ($response -and $response.Length -ge 20) {
      Write-Ok "STUN server replied — outbound UDP exits this network"
    } else {
      Write-Warn "Got a response but it looks malformed (length $($response.Length))"
    }
  } catch [System.Net.Sockets.SocketException] {
    $code = $_.Exception.SocketErrorCode
    if ($code -eq 'TimedOut') {
      Write-Fail "No STUN response — outbound UDP is likely being silently dropped"
      Write-Hint  "WireGuard and most VPN UDP modes will not work on this network; try OpenVPN-over-TCP or an SSL VPN on port 443"
    } else {
      Write-Fail "UDP socket error: $code"
    }
  } finally {
    $udp.Close()
  }
}

# ─── check 5: vpn port matrix ────────────────────────────────────────────────

function Test-VpnPorts {
  Write-Header 'VPN port reachability'
  Write-Info  "Testing against $TRACE_TARGET — a success means the port reaches the internet, not your specific VPN server"

  $VPN_PORTS | ForEach-Object {
    $entry = $_

    if ($entry.Proto -eq 'TCP') {
      $client = [System.Net.Sockets.TcpClient]::new()
      try {
        $task = $client.ConnectAsync($TRACE_TARGET, $entry.Port)
        $done = $task.Wait(1500)
        if ($done -and $client.Connected) {
          Write-Ok   "TCP $($entry.Port)  open    [$($entry.Label)]"
        } else {
          Write-Fail "TCP $($entry.Port)  blocked [$($entry.Label)]"
        }
      } catch {
        Write-Fail   "TCP $($entry.Port)  blocked [$($entry.Label)]  ($($_.Exception.InnerException.Message))"
      } finally {
        $client.Close()
      }
      return
    }

    # UDP — send a tiny payload and check for any ICMP port-unreachable back
    # silence means filtered (dropped), ICMP back means the port exists but nothing is listening
    $udp = [System.Net.Sockets.UdpClient]::new()
    $udp.Client.ReceiveTimeout = 1200
    try {
      $probe = [byte[]](0x00, 0x00)
      $udp.Send($probe, $probe.Length, $TRACE_TARGET, $entry.Port) | Out-Null
      $ep  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
      $udp.Receive([ref]$ep) | Out-Null
      Write-Warn "UDP $($entry.Port)  got response (unexpected for this target) [$($entry.Label)]"
    } catch [System.Net.Sockets.SocketException] {
      if ($_.Exception.SocketErrorCode -eq 'TimedOut') {
        # silence = either filtered/dropped, or open with no reply — both are "passes" for VPN
        Write-Ok   "UDP $($entry.Port)  passes (no block detected) [$($entry.Label)]"
      } elseif ($_.Exception.SocketErrorCode -eq 'ConnectionReset') {
        Write-Ok   "UDP $($entry.Port)  ICMP unreachable (port closed at target but packet reached internet) [$($entry.Label)]"
      } else {
        Write-Fail "UDP $($entry.Port)  socket error: $($_.Exception.SocketErrorCode) [$($entry.Label)]"
      }
    } finally {
      $udp.Close()
    }
  }
}

# ─── check 6: mtu path discovery ─────────────────────────────────────────────

function Test-PathMtu {
  Write-Header "Path MTU discovery  ($MTU_TARGET)"
  Write-Info  "Binary-searching for the largest packet size that reaches the target without fragmentation"
  Write-Info  "This may take a few seconds..."

  $lo = $MTU_MIN
  $hi = $MTU_MAX

  # The ICMP data payload is packet size minus the 28 bytes of IP+ICMP headers
  $probe = {
    param([int]$size)
    # ping with -f (DF bit, no fragmentation) and -l (payload size minus 28 for headers)
    $payloadSize = [Math]::Max(0, $size - 28)
    $result = ping -n 1 -f -l $payloadSize -w $MTU_TIMEOUT_MS $MTU_TARGET 2>&1
    $result -match 'Reply from' -or $result -match 'TTL='
  }

  # quick sanity check — if the min MTU itself fails we have bigger problems
  if (-not (& $probe $lo)) {
    Write-Fail "Even a $lo byte packet does not reach $MTU_TARGET"
    Write-Hint  "No meaningful ICMP path exists — captive portal, or ICMP is being blocked entirely"
    return
  }

  while ($lo -lt $hi - 1) {
    $mid = [Math]::Floor(($lo + $hi) / 2)
    if (& $probe $mid) { $lo = $mid } else { $hi = $mid }
  }

  $pathMtu = $lo
  Write-Ok "Path MTU: $pathMtu bytes"

  if ($pathMtu -eq $MTU_MAX) {
    Write-Info  "Full 1500 byte MTU — no fragmentation constraints on this path"
  } else {
    Write-Warn "Path MTU is below the Ethernet standard of 1500"
    if ($pathMtu -lt 1280) {
      Write-Fail "Below 1280 — this breaks IPv6 (minimum required MTU) and will cause issues with most VPN protocols"
    }
    $VPN_OVERHEAD.GetEnumerator() | ForEach-Object {
      $available = $pathMtu - $_.Value
      $label = $_.Key
      if ($available -lt 576) {
        Write-Fail "$label  needs at least $($_.Value) bytes overhead — only $available bytes left for payload, unusable"
      } elseif ($available -lt 1200) {
        Write-Warn "$label  available payload: $available bytes (working but poor throughput)"
      } else {
        Write-Ok   "$label  available payload: $available bytes"
      }
    }
    Write-Hint "Set your VPN client's MTU to $pathMtu or lower, or enable MSS clamping if your router allows it"
  }
}

# ─── check 7: traceroute to first public hop ─────────────────────────────────

function Test-Hops {
  Write-Header "Route to $TRACE_TARGET (first 10 hops)"

  $hops = tracert -d -h 10 -w 500 $TRACE_TARGET 2>&1

  $privateRanges = @(
    '10\.\d+\.\d+\.\d+',
    '172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
    '192\.168\.\d+\.\d+'
  )

  $lastPrivateHop = $null
  $firstPublicHop = $null
  $firstTimeout   = $null

  $hops | Select-String -Pattern '^\s*\d+' | ForEach-Object {
    $line = $_.Line.Trim()
    $ip = if ($line -match '(\d+\.\d+\.\d+\.\d+)') { $Matches[1] } else { $null }

    if ($null -eq $ip) {
      if ($line -match '\*') {
        if ($null -eq $firstTimeout) { $firstTimeout = $line }
      }
      return
    }

    $isPrivate = $privateRanges | Where-Object { $ip -match $_ }
    if ($isPrivate) {
      $lastPrivateHop = $ip
      Write-Info "  (local)  $line"
    } else {
      if ($null -eq $firstPublicHop) { $firstPublicHop = $ip }
      Write-Info "  (public) $line"
    }
  }

  if ($null -ne $firstTimeout -and $null -eq $firstPublicHop) {
    Write-Warn "Packets stop responding at the network boundary — traffic is likely hitting a filter before reaching the internet"
    Write-Info  "Last responding private hop: $lastPrivateHop"
    Write-Hint  "Ask the network admin whether the AP applies outbound filtering, or check for a captive portal"
    return
  }

  if ($null -ne $firstPublicHop) {
    Write-Ok "Traffic reaches the public internet via $firstPublicHop"
    if ($null -ne $lastPrivateHop) {
      Write-Info "Last private hop before the internet: $lastPrivateHop"
    }
  }
}

# ─── main ────────────────────────────────────────────────────────────────────

Write-Host "`nmoz-conn-checker  —  network diagnostic" -ForegroundColor Cyan
Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  ✓ green = working  ▲ yellow = degraded/warning  ✗ red = broken" -ForegroundColor DarkGray

Test-Dns
Test-HttpsReachability
Test-ProxyConfig
Test-UdpStun
Test-VpnPorts
Test-PathMtu
Test-Hops

Write-Host "`n─────────────────────────────────────────`n" -ForegroundColor DarkGray
