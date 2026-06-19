create policy "Public orders insert"
on public.orders
for insert
with check (true);
