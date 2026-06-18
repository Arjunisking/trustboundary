export async function POST(request: Request) {
  await supabase.from("orders").upsert(await request.json());

  return Response.json({ ok: true });
}
