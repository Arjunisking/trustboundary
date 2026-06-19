create policy "Profile owner update"
on public.profiles
for update
using (auth.uid() = user_id)
with check (auth.uid() = user_id);
