-- =========================================================
-- CTH HOSTING
-- SUPABASE DATABASE + RLS + STORAGE SECURITY
-- CREDIT: SHADOW JOKER
-- =========================================================


-- ---------------------------------------------------------
-- PROFILES
-- ---------------------------------------------------------

create table if not exists public.profiles (

    id uuid primary key
        references auth.users(id)
        on delete cascade,

    username text not null,

    created_at timestamptz
        default now()

);


-- ---------------------------------------------------------
-- UNIQUE USERNAME
--
-- Case insensitive:
--
-- ShadowJoker
-- shadowjoker
-- SHADOWJOKER
--
-- all treated as same username.
-- ---------------------------------------------------------

create unique index
if not exists profiles_username_lower_unique
on public.profiles (lower(username));


-- ---------------------------------------------------------
-- FILES
-- ---------------------------------------------------------

create table if not exists public.files (

    id uuid primary key
        default gen_random_uuid(),

    user_id uuid not null
        references auth.users(id)
        on delete cascade,

    file_name text not null,

    file_path text not null,

    file_size bigint not null
        default 0,

    mime_type text,

    created_at timestamptz
        default now()

);


-- ---------------------------------------------------------
-- INDEX
-- ---------------------------------------------------------

create index
if not exists files_user_id_idx
on public.files(user_id);


-- ---------------------------------------------------------
-- ENABLE RLS
-- ---------------------------------------------------------

alter table public.profiles
enable row level security;

alter table public.files
enable row level security;


-- =========================================================
-- PROFILE POLICIES
-- =========================================================

drop policy if exists
"Users can view own profile"
on public.profiles;

create policy
"Users can view own profile"
on public.profiles

for select

to authenticated

using (
    id = auth.uid()
);


drop policy if exists
"Users can create own profile"
on public.profiles;

create policy
"Users can create own profile"
on public.profiles

for insert

to authenticated

with check (
    id = auth.uid()
);


drop policy if exists
"Users can update own profile"
on public.profiles;

create policy
"Users can update own profile"
on public.profiles

for update

to authenticated

using (
    id = auth.uid()
)

with check (
    id = auth.uid()
);


-- =========================================================
-- FILE POLICIES
-- =========================================================

drop policy if exists
"Users can view own files"
on public.files;

create policy
"Users can view own files"
on public.files

for select

to authenticated

using (
    user_id = auth.uid()
);


drop policy if exists
"Users can insert own files"
on public.files;

create policy
"Users can insert own files"
on public.files

for insert

to authenticated

with check (
    user_id = auth.uid()
);


drop policy if exists
"Users can delete own files"
on public.files;

create policy
"Users can delete own files"
on public.files

for delete

to authenticated

using (
    user_id = auth.uid()
);


drop policy if exists
"Users can update own files"
on public.files;

create policy
"Users can update own files"
on public.files

for update

to authenticated

using (
    user_id = auth.uid()
)

with check (
    user_id = auth.uid()
);


-- =========================================================
-- PRIVATE STORAGE
-- =========================================================

insert into storage.buckets
(
    id,
    name,
    public
)

values
(
    'files',
    'files',
    false
)

on conflict (id)
do update set
public = false;


-- =========================================================
-- STORAGE SECURITY
--
-- Every file must be inside:
--
-- USER_UUID/filename
--
-- Example:
--
-- 12345678-....../abc-file.zip
--
-- =========================================================


drop policy if exists
"CTH users can upload own files"
on storage.objects;

create policy
"CTH users can upload own files"

on storage.objects

for insert

to authenticated

with check (

    bucket_id = 'files'

    and

    (storage.foldername(name))[1]
    = (auth.uid())::text

);


drop policy if exists
"CTH users can view own files"
on storage.objects;

create policy
"CTH users can view own files"

on storage.objects

for select

to authenticated

using (

    bucket_id = 'files'

    and

    (storage.foldername(name))[1]
    = (auth.uid())::text

);


drop policy if exists
"CTH users can delete own files"
on storage.objects;

create policy
"CTH users can delete own files"

on storage.objects

for delete

to authenticated

using (

    bucket_id = 'files'

    and

    (storage.foldername(name))[1]
    = (auth.uid())::text

);


drop policy if exists
"CTH users can update own files"
on storage.objects;

create policy
"CTH users can update own files"

on storage.objects

for update

to authenticated

using (

    bucket_id = 'files'

    and

    (storage.foldername(name))[1]
    = (auth.uid())::text

)

with check (

    bucket_id = 'files'

    and

    (storage.foldername(name))[1]
    = (auth.uid())::text

);


-- =========================================================
-- AUTO CREATE PROFILE
-- =========================================================

create or replace function
public.handle_new_user()

returns trigger

language plpgsql

security definer

set search_path = public

as $$

begin

    insert into public.profiles
    (
        id,
        username
    )

    values
    (
        new.id,

        lower(
            coalesce(
                new.raw_user_meta_data->>'username',
                split_part(new.email,'@',1)
            )
        )
    )

    on conflict (id)
    do nothing;

    return new;

end;

$$;


drop trigger if exists
on_auth_user_created
on auth.users;


create trigger
on_auth_user_created

after insert

on auth.users

for each row

execute procedure
public.handle_new_user();
