export async function POST(req: Request) {
  const data = await req.json();
  await db.user.create({ data });

  return Response.json({ ok: true });
}
