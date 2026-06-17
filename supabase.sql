create table if not exists public.reports (
  id bigint generated always as identity primary key,
  received_at timestamptz not null default now(),
  client_timestamp timestamptz not null,
  results jsonb not null
);

alter table public.reports enable row level security;

create policy "anon can insert reports"
  on public.reports
  for insert
  to anon
  with check (true);

-- no select policy for anon, reports are write only from the client
-- read them from the dashboard or a service-role key
