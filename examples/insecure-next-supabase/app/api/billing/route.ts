export async function GET() {
  const session = await getServerSession();
  if (!session?.user?.id) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const invoices = await prisma.invoice.findMany();
  return Response.json(invoices);
}
