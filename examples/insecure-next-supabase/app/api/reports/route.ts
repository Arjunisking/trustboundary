export async function GET() {
  const rows = await supabase.from("reports").select("*");
  return Response.json(rows);
}
