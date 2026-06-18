export async function POST(request: Request) {
  const payload = await request.json();
  await supabase.from("profiles").update(payload);

  return Response.json({ ok: true });
}
