export async function POST(request: Request) {
  const payload = await request.json();
  await db.order.update({ data: payload });

  return Response.json({ ok: true });
}
