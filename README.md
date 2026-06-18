# moz-conn-checker
Simplified network diagnostics for non-technical users

## What it checks

Runs from the toolbar popup, four checks against the current network: DNS
resolution (compared against a DNS-over-HTTPS lookup, to catch local DNS
blocking even when the name resolves fine elsewhere), HTTPS reachability on
port 443, outbound UDP reachability via WebRTC ICE gathering (the only way to
test UDP from inside the extension sandbox), and whether a system proxy is
configured. Each check reports in plain language, using Firefox's own
NS_ERROR_* / SEC_ERROR_* codes from webRequest.onErrorOccurred to tell apart
DNS failure, connection refused, reset, timeout, and TLS interception.

Out of scope for now: confirming a specific VPN port (1194, 51820, ...) is
open. That needs a real socket, which the extension sandbox does not allow.
The UDP check is the closest available proxy for that.

## Load it locally

Firefox -> about:debugging -> This Firefox -> Load Temporary Add-on -> pick
manifest.json. Reload after editing background.js or popup.js.

Permanent distribution to other people requires signing through
addons.mozilla.org (listed or unlisted), Firefox release builds refuse
unsigned extensions.

## Reports

Every run is queued in browser.storage.local. An alarm retries the upload to
Supabase every 5 minutes once CONFIG.supabaseUrl and CONFIG.supabaseAnonKey
in background.js are filled in; see supabase.sql for the table and the
insert-only RLS policy. tests/upload.hurl checks that contract independently
of the extension, run with:

hurl --variable supabase_url=https://yourproject.supabase.co \
     --variable supabase_anon_key=your_anon_key \
     tests/checks.hurl \
     tests/upload.hurl

## PowerShell diagnostics (Windows)

`diagnose.ps1` runs the same checks plus things the browser extension cannot
reach: raw TCP/UDP port probes for common VPN protocols (OpenVPN, WireGuard,
IKEv2, PPTP), ICMP-based path MTU discovery via binary search with the DF bit
set, and a traceroute to locate where packets stop responding.

No elevation needed, no dependencies beyond what ships with Windows 10+.

    Set-ExecutionPolicy -Scope Process Bypass
    .\diagnose.ps1

To distribute to users without touching execution policy:

    powershell -ExecutionPolicy Bypass -File diagnose.ps1

Or wrap it in a .bat file with that command so they just double-click it.

