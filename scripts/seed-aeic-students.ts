/**
 * seed-aeic-students.ts
 *
 * One-off script to seed the initial AEIC student cohort into Supabase.
 * Run via:  npm run seed:aeic
 *
 * For each student:
 *   1. Creates a Supabase Auth user (admin API) with a synthetic email
 *      and a random temporary password.
 *   2. Inserts a `profiles` row (role='student') linked to that auth user.
 *   3. Skips (with a warning) if the matric_number already exists.
 *
 * Requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env
 */

import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
import crypto from "node:crypto";

// ─── Config ──────────────────────────────────────────────────────────────────

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌  Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env");
  console.error("   Copy .env.example to .env and fill in your project credentials.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// ─── Student data ────────────────────────────────────────────────────────────

interface StudentSeed {
  name: string;
  matric: string;
}

const STUDENTS: StudentSeed[] = [
  { name: "Adegboye Michael Adeoluwa",       matric: "2022/1/86885ET" },
  { name: "Abolarinwa Samuel Ayomide",       matric: "2022/1/86871ET" },
  { name: "Aisuedion Osemudiamen Blessed",   matric: "2022/1/86884ET" },
  { name: "Eje Obed Honour",                 matric: "2022/1/84974ET" },
  { name: "Folorunsho Promise",              matric: "BU23MCT1014" },
  { name: "Ibinaiye Omolade Praise-God",     matric: "22BF008862" },
  { name: "Iruke Chinonso Solomon",          matric: "2022/1/86868ET" },
  { name: "Daberenachi Abundant Joel",       matric: "2022/1/88934ET" },
  { name: "Rasak Khalid Abiodun",            matric: "2022/1/86873ET" },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Convert matric to a safe email-local-part: lowercase, alphanumeric only. */
function matricToEmail(matric: string): string {
  const local = matric.toLowerCase().replace(/[^a-z0-9]/g, "");
  return `${local}@attendclass.local`;
}

/** Generate a random 16-char temporary password. */
function randomPassword(): string {
  return crypto.randomBytes(12).toString("base64url"); // 16 chars, URL-safe
}

// ─── Main ────────────────────────────────────────────────────────────────────

interface Result {
  name: string;
  matric: string;
  email: string;
  password: string;
  status: "created" | "skipped" | "error";
  note: string;
}

async function main() {
  console.log("🎓  Seeding AEIC students into AttendClass v2...\n");

  const results: Result[] = [];

  for (const student of STUDENTS) {
    const email = matricToEmail(student.matric);
    const password = randomPassword();

    const result: Result = {
      name: student.name,
      matric: student.matric,
      email,
      password,
      status: "error",
      note: "",
    };

    // ── Check if matric already exists in profiles ─────────────────────────
    const { data: existing, error: lookupErr } = await supabase
      .from("profiles")
      .select("id")
      .eq("matric_number", student.matric)
      .maybeSingle();

    if (lookupErr) {
      result.note = `Profile lookup failed: ${lookupErr.message}`;
      results.push(result);
      continue;
    }

    if (existing) {
      result.status = "skipped";
      result.password = "(not created)";
      result.note = `Matric ${student.matric} already exists in profiles`;
      console.warn(`⚠️  Skipping ${student.name} — matric already exists`);
      results.push(result);
      continue;
    }

    // ── Create Auth user ──────────────────────────────────────────────────
    const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true, // auto-confirm so they can log in immediately
      user_metadata: {
        full_name: student.name,
        matric_number: student.matric,
      },
    });

    if (authErr) {
      result.note = `Auth createUser failed: ${authErr.message}`;
      console.error(`❌  Failed to create auth user for ${student.name}: ${authErr.message}`);
      results.push(result);
      continue;
    }

    const userId = authData.user.id;

    // ── Insert profile row ────────────────────────────────────────────────
    const { error: profileErr } = await supabase.from("profiles").insert({
      id: userId,
      role: "user",
      full_name: student.name,
      matric_number: student.matric,
    });

    if (profileErr) {
      result.note = `Auth user created (${userId}) but profile insert failed: ${profileErr.message}`;
      console.error(`❌  Profile insert failed for ${student.name}: ${profileErr.message}`);
      results.push(result);
      continue;
    }

    result.status = "created";
    result.note = userId;
    console.log(`✅  ${student.name} (${student.matric})`);
    results.push(result);
  }

  // ── Summary table ─────────────────────────────────────────────────────────
  console.log("\n" + "═".repeat(120));
  console.log("  SEED RESULTS");
  console.log("═".repeat(120));

  // Format as a nice table
  const created = results.filter((r) => r.status === "created");
  const skipped = results.filter((r) => r.status === "skipped");
  const errors  = results.filter((r) => r.status === "error");

  if (created.length > 0) {
    console.log("\n🟢 Created students & temporary passwords:\n");
    console.table(
      created.map((r) => ({
        Name: r.name,
        Matric: r.matric,
        Email: r.email,
        "Temp Password": r.password,
        "User ID": r.note,
      }))
    );
  }

  if (skipped.length > 0) {
    console.log("\n🟡 Skipped (already exist):\n");
    console.table(
      skipped.map((r) => ({
        Name: r.name,
        Matric: r.matric,
        Reason: r.note,
      }))
    );
  }

  if (errors.length > 0) {
    console.log("\n🔴 Errors:\n");
    console.table(
      errors.map((r) => ({
        Name: r.name,
        Matric: r.matric,
        Error: r.note,
      }))
    );
  }

  console.log(
    `\nTotal: ${created.length} created, ${skipped.length} skipped, ${errors.length} errors\n`
  );

  // Exit with error code if anything failed
  if (errors.length > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("💥 Unexpected error:", err);
  process.exit(1);
});
