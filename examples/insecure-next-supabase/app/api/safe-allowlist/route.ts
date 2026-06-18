export async function POST(request: Request) {
  const body = await request.json();
  await supabase.from("users").insert({
    name: body.name,
    email: body.email
  });

  return Response.json({ ok: true });
}
