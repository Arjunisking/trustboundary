export async function POST(request: Request) {
  const body = await request.json();
  await supabase.from("users").insert(body);

  return Response.json({ ok: true });
}
