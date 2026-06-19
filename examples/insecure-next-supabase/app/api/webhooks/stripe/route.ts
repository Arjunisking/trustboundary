export async function POST(request: Request) {
  const body = await request.text();
  await prisma.event.create({ data: { payload: body } });

  return Response.json({ ok: true });
}
