/**
 * manage-students — Supabase Edge Function
 *
 * Allows administrators to add users (single or bulk) to the system.
 * Creates Supabase Auth users and profiles rows. Requires a valid JWT
 * from a user with role='administrator'.
 *
 * POST /manage-students
 * Authorization: Bearer <jwt>
 * Content-Type: application/json
 * Body: { students: [{ name: string, matric: string }] }
 *
 * Response: { created: [...], skipped: [...] }
 */

import { createClient } from "jsr:@supabase/supabase-js@2";

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Derive surname as the FIRST word of the full name (Nigerian naming convention). */
function deriveSurname(fullName: string): string {
  return fullName.trim().split(/\s+/)[0]?.toLowerCase() ?? "changeme";
}

/** Convert matric to a safe email-local-part: lowercase, alphanumeric only. */
function matricToEmail(matric: string): string {
  const local = matric.toLowerCase().replace(/[^a-z0-9]/g, "");
  return `${local}@attendclass.local`;
}

/** Build a JSON response. */
function json(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    },
  });
}

// ─── Main handler ────────────────────────────────────────────────────────────

Deno.serve(async (req: Request): Promise<Response> => {
  // ── CORS preflight ───────────────────────────────────────────────────────
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
      },
    });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  // ── Extract and verify JWT ───────────────────────────────────────────────
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return json({ error: "Missing or invalid Authorization header" }, 401);
  }
  const token = authHeader.replace("Bearer ", "");

  // Admin client — uses service role key to bypass RLS and call admin APIs
  const supabaseAdmin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  // Verify the JWT and get the calling user
  const { data: { user: caller }, error: authErr } = await supabaseAdmin.auth.getUser(token);
  if (authErr || !caller) {
    return json({ error: "Invalid or expired token" }, 401);
  }

  // ── Check caller's role ──────────────────────────────────────────────────
  const { data: callerProfile, error: profileErr } = await supabaseAdmin
    .from("profiles")
    .select("role")
    .eq("id", caller.id)
    .single();

  if (profileErr || !callerProfile) {
    return json({ error: "Caller profile not found" }, 403);
  }

  if (callerProfile.role !== "administrator") {
    return json({ error: "Forbidden — only administrators can manage users" }, 403);
  }

  // ── Parse request body ───────────────────────────────────────────────────
  let body: { students?: Array<{ name: string; matric: string }> };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  if (!body.students || !Array.isArray(body.students) || body.students.length === 0) {
    return json({ error: "Body must contain a non-empty 'students' array" }, 400);
  }

  // ── Process each student ─────────────────────────────────────────────────
  const created: Array<{ name: string; matric: string; email: string }> = [];
  const skipped: Array<{ name: string; matric: string; reason: string }> = [];

  for (const student of body.students) {
    const name = student.name?.trim();
    const matric = student.matric?.trim();

    if (!name || !matric) {
      skipped.push({
        name: name || "(empty)",
        matric: matric || "(empty)",
        reason: "Name and matric number are both required",
      });
      continue;
    }

    // Check for existing matric in profiles
    const { data: existing } = await supabaseAdmin
      .from("profiles")
      .select("id")
      .eq("matric_number", matric)
      .maybeSingle();

    if (existing) {
      skipped.push({ name, matric, reason: "Duplicate matric number — user already exists" });
      continue;
    }

    const email = matricToEmail(matric);
    const password = deriveSurname(name);

    // Create auth user via admin API (requires service role key)
    const { data: authData, error: createErr } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        full_name: name,
        matric_number: matric,
      },
    });

    if (createErr) {
      // Handle duplicate email (could happen if matric was reformatted)
      if (createErr.message?.includes("already been registered")) {
        skipped.push({ name, matric, reason: "Email already registered (derived from matric)" });
      } else {
        skipped.push({ name, matric, reason: `Auth error: ${createErr.message}` });
      }
      continue;
    }

    const userId = authData.user.id;

    // Insert profile row with must_reset_password = true
    const { error: insertErr } = await supabaseAdmin.from("profiles").insert({
      id: userId,
      role: "user",
      full_name: name,
      matric_number: matric,
      must_reset_password: true,
    });

    if (insertErr) {
      // Auth user was created but profile insert failed — log but still report
      console.error(`Profile insert failed for ${matric}: ${insertErr.message}`);
      skipped.push({
        name,
        matric,
        reason: `Auth user created but profile insert failed: ${insertErr.message}`,
      });
      continue;
    }

    created.push({ name, matric, email });
    console.log(`Created user: ${name} (${matric})`);
  }

  // ── Return summary ───────────────────────────────────────────────────────
  console.log(`manage-students: ${created.length} created, ${skipped.length} skipped`);

  return json({ created, skipped });
});
