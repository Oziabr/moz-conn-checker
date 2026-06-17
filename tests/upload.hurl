POST {{supabase_url}}/rest/v1/reports
apikey: {{supabase_anon_key}}
Authorization: Bearer {{supabase_anon_key}}
Content-Type: application/json
Prefer: return=minimal

[
  {
    "client_timestamp": "2026-06-17T12:00:00.000Z",
    "results": [
      { "id": "dns", "label": "DNS resolution", "status": "ok", "detail": "system DNS resolves and reaches the test host" }
    ]
  }
]

HTTP 201
