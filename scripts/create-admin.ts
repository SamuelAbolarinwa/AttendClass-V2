/**
 * create-admin.ts — One-off script to create the first administrator account.
 * Run AFTER the 0003_rename_roles migration has been pushed.
 *
 * Usage:  npx tsx scripts/create-admin.ts
 */

import "dotenv/config";
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌  Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const EMAIL = "admin@attendclass.local"; // added .local to ensure it passes email validation
const PASSWORD = "attendclass";
const FULL_NAME = "Samuel Abolarinwa";

async function main() {
  console.log("🔧 Creating administrator account...\n");

  // Step 1: Create auth user
  const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
    email: EMAIL,
    password: PASSWORD,
    email_confirm: true,
    user_metadata: { full_name: FULL_NAME },
  });

  if (authErr) {
    console.error("❌ Auth user creation failed:", authErr.message);
    process.exit(1);
  }

  const userId = authData.user.id;
  console.log(`✅ Auth user created: ${userId}`);

  // Step 2: Upsert profile row
  const { error: profileErr } = await supabase.from("profiles").upsert(
    {
      id: userId,
      role: "administrator",
      full_name: FULL_NAME,
      matric_number: null,
      must_reset_password: false,
    },
    { onConflict: "id" },
  );

  if (profileErr) {
    console.error("❌ Profile upsert failed:", profileErr.message);
    process.exit(1);
  }

  console.log("✅ Profile row inserted\n");

  // Step 3: Confirm by querying back
  const { data: profile, error: queryErr } = await supabase
    .from("profiles")
    .select("*")
    .eq("id", userId)
    .single();

  if (queryErr) {
    console.error("⚠️  Query failed:", queryErr.message);
  } else {
    console.log("📋 Resulting profiles row:");
    console.table([profile]);
  }

  // Output credentials
  console.log("\n" + "═".repeat(60));
  console.log("  LOGIN CREDENTIALS");
  console.log("═".repeat(60));
  console.log(`  Email:    ${EMAIL}`);
  console.log(`  Password: ${PASSWORD}`);
  console.log(`  Role:     administrator`);
  console.log("═".repeat(60) + "\n");
}

main().catch((err) => {
  console.error("💥 Unexpected error:", err);
  process.exit(1);
});
