# ── check 1: DNS-over-HTTPS endpoint ─────────────────────────────────────────
GET https://mozilla.cloudflare-dns.com/dns-query?name=example.org&type=A
Accept: application/dns-json

HTTP 200
[Asserts]
header "content-type" contains "application/dns-json"
jsonpath "$.Status" == 0
jsonpath "$.Answer" count > 0


# ── check 2: Supabase report insert ──────────────────────────────────────────
POST {{supabase_url}}/rest/v1/reports
apikey: {{supabase_anon_key}}
Authorization: Bearer {{supabase_anon_key}}
Content-Type: application/json
Prefer: return=minimal

[
  {
    "client_timestamp": "2026-06-17T12:00:00.000Z",
    "results": [
      { "id": "dns",      "label": "DNS resolution",          "status": "ok",   "detail": "system DNS resolves and reaches the test host" },
      { "id": "tcp443",   "label": "HTTPS reachability",      "status": "ok",   "detail": "all targets reachable" },
      { "id": "udp",      "label": "Outbound UDP (STUN)",     "status": "ok",   "detail": "STUN server replied" },
      { "id": "proxy",    "label": "Proxy configuration",     "status": "ok",   "detail": "no proxy configured" },
      { "id": "mtu",      "label": "Path MTU",                "status": "ok",   "detail": "1500" },
      { "id": "tracert",  "label": "First public hop",        "status": "ok",   "detail": "1.1.1.1" }
    ]
  }
]

HTTP 201
