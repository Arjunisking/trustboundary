export async function POST(request: Request) {
  const body = await request.json();
  const parsed = schema.parse(body);
  await supabase.from("users").insert(parsed);

  return Response.json({ ok: true });
}
