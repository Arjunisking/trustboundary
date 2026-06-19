export async function GET() {
  const session = await getServerSession();
  if (!session?.user?.id) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const user = await prisma.user.findUnique({
    where: {
      userId: session.user.id
    }
  });

  return Response.json(user);
}
