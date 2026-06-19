export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session?.user?.id) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const parsed = schema.parse(body);
  await supabase.from("users").insert({
    ...parsed,
    userId: session.user.id
  });

  return Response.json({ ok: true });
}
