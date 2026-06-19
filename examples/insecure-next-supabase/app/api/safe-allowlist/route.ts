export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session?.user?.id) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  await supabase.from("users").insert({
    name: body.name,
    email: body.email,
    userId: session.user.id
  });

  return Response.json({ ok: true });
}
