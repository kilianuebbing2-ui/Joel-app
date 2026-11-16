-- Tagwerk Update: Schlaf-Automatik über die Kurzbefehle-App
-- Einmal im Supabase SQL Editor ausführen (alles einfügen → Run).
-- Der Kurzbefehl schickt Einschlaf- und Aufwachzeit mit einem geheimen Token.
-- Die App holt die Werte beim nächsten Öffnen ab und trägt sie ein.

-- 1) Posteingang für Werte vom Kurzbefehl
create table if not exists public.inbox (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references auth.users (id) on delete cascade,
  kind       text not null,
  payload    jsonb not null,
  created_at timestamptz not null default now()
);
alter table public.inbox enable row level security;
grant select, delete on public.inbox to authenticated;

drop policy if exists "Eigenen Posteingang lesen" on public.inbox;
drop policy if exists "Eigenen Posteingang leeren" on public.inbox;
create policy "Eigenen Posteingang lesen" on public.inbox
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "Eigenen Posteingang leeren" on public.inbox
  for delete to authenticated using ((select auth.uid()) = user_id);

-- 2) Geheimer Token pro Konto (wird in der App erzeugt)
create table if not exists public.shortcut_tokens (
  user_id uuid primary key references auth.users (id) on delete cascade,
  token   text not null unique check (length(token) >= 32)
);
alter table public.shortcut_tokens enable row level security;
grant select, insert, update, delete on public.shortcut_tokens to authenticated;

drop policy if exists "Eigenen Token lesen" on public.shortcut_tokens;
drop policy if exists "Eigenen Token anlegen" on public.shortcut_tokens;
drop policy if exists "Eigenen Token ändern" on public.shortcut_tokens;
drop policy if exists "Eigenen Token löschen" on public.shortcut_tokens;
create policy "Eigenen Token lesen" on public.shortcut_tokens
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "Eigenen Token anlegen" on public.shortcut_tokens
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "Eigenen Token ändern" on public.shortcut_tokens
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Eigenen Token löschen" on public.shortcut_tokens
  for delete to authenticated using ((select auth.uid()) = user_id);

-- 3) Funktion, die der Kurzbefehl aufruft (nur mit gültigem Token)
create or replace function public.push_sleep(p_token text, p_start timestamptz, p_end timestamptz)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user uuid;
begin
  select user_id into v_user from public.shortcut_tokens where token = p_token;
  if v_user is null then
    raise exception 'Ungültiger Token';
  end if;
  if p_end <= p_start or p_end - p_start > interval '20 hours' then
    raise exception 'Ungültige Schlafzeiten';
  end if;
  insert into public.inbox (user_id, kind, payload)
  values (v_user, 'sleep', jsonb_build_object('start', p_start, 'end', p_end));
  return 'ok';
end;
$$;

revoke all on function public.push_sleep(text, timestamptz, timestamptz) from public;
grant execute on function public.push_sleep(text, timestamptz, timestamptz) to anon, authenticated;
