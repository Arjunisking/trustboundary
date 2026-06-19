export async function GET() {
  const user = await supabase.auth.getUser();
  if (!user.data.user) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const profile = await supabase
    .from("profiles")
    .select("*")
    .eq("userId", user.data.user.id);

  return Response.json(profile);
}
