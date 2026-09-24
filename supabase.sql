-- ==========================================
-- CTH HOSTING FINAL DATABASE
-- ==========================================

-- পুরনো signup trigger/function থাকলে সরিয়ে দেবে
DROP TRIGGER IF EXISTS on_auth_user_created
ON auth.users;

DROP FUNCTION IF EXISTS public.handle_new_user();


-- ==========================================
-- FILES TABLE
-- ==========================================

CREATE TABLE IF NOT EXISTS public.files (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id uuid NOT NULL
        REFERENCES auth.users(id)
        ON DELETE CASCADE,

    file_name text NOT NULL,

    file_path text NOT NULL,

    file_size bigint NOT NULL DEFAULT 0,

    mime_type text,

    created_at timestamptz NOT NULL DEFAULT now()
);


CREATE INDEX IF NOT EXISTS files_user_id_idx
ON public.files(user_id);

CREATE INDEX IF NOT EXISTS files_created_at_idx
ON public.files(created_at DESC);


-- ==========================================
-- RLS
-- ==========================================

ALTER TABLE public.files ENABLE ROW LEVEL SECURITY;


DROP POLICY IF EXISTS "files_select_own"
ON public.files;

DROP POLICY IF EXISTS "files_insert_own"
ON public.files;

DROP POLICY IF EXISTS "files_update_own"
ON public.files;

DROP POLICY IF EXISTS "files_delete_own"
ON public.files;


-- নিজের ফাইল শুধু নিজে দেখতে পারবে
CREATE POLICY "files_select_own"
ON public.files
FOR SELECT
TO authenticated
USING (
    user_id = auth.uid()
);


-- নিজের ফাইল metadata তৈরি করতে পারবে
CREATE POLICY "files_insert_own"
ON public.files
FOR INSERT
TO authenticated
WITH CHECK (
    user_id = auth.uid()
);


-- নিজের metadata update
CREATE POLICY "files_update_own"
ON public.files
FOR UPDATE
TO authenticated
USING (
    user_id = auth.uid()
)
WITH CHECK (
    user_id = auth.uid()
);


-- নিজের ফাইল delete
CREATE POLICY "files_delete_own"
ON public.files
FOR DELETE
TO authenticated
USING (
    user_id = auth.uid()
);
