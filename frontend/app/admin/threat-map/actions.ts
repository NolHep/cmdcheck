"use server";

const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";
const adminSecret = process.env.ADMIN_SECRET ?? "";

function headers() {
  return { "Content-Type": "application/json", "X-Admin-Secret": adminSecret };
}

export async function createGroup(name: string, description: string) {
  const res = await fetch(`${backendUrl}/admin/threat-groups`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ name, description: description || null }),
  });
  if (!res.ok) throw new Error("Failed to create group");
  return res.json();
}

export async function deleteGroup(groupId: string) {
  const res = await fetch(`${backendUrl}/admin/threat-groups/${groupId}`, {
    method: "DELETE",
    headers: headers(),
  });
  if (!res.ok) throw new Error("Failed to delete group");
}

export async function addMember(groupId: string, slug: string, notes: string) {
  const res = await fetch(`${backendUrl}/admin/threat-groups/${groupId}/members`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ slug, notes: notes || null }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail?.detail ?? "Failed to add analysis");
  }
  return res.json();
}

export async function removeMember(groupId: string, slug: string) {
  const res = await fetch(`${backendUrl}/admin/threat-groups/${groupId}/members/${slug}`, {
    method: "DELETE",
    headers: headers(),
  });
  if (!res.ok) throw new Error("Failed to remove member");
}
