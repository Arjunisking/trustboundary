"use client";

const adminKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;

export default function AdminPage() {
  return <pre>{adminKey}</pre>;
}
