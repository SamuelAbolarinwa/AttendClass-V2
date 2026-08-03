const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');

dotenv.config();

const url = process.env.SUPABASE_URL;
const anonKey = process.env.VITE_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(url, anonKey);
const supabaseAdmin = createClient(url, serviceKey);

async function run() {
  const dummyIdentifier = 'test_logout_user@example.com';
  const dummyPassword = 'password123';
  const hash = bcrypt.hashSync(dummyPassword, 10);
  
  console.log("1. Creating/Updating dummy profile...");
  // Check if profile exists
  let { data: existing } = await supabaseAdmin.from('profiles').select('id').eq('identifier', dummyIdentifier).single();
  
  if (!existing) {
    const { data: newProfile, error } = await supabaseAdmin.from('profiles').insert({
      identifier: dummyIdentifier,
      password_hash: hash,
      role: 'user',
      full_name: 'Test Logout User'
    }).select('id').single();
    
    if (error) {
      console.error("Error creating dummy profile:", error);
      return;
    }
    existing = newProfile;
  } else {
    // Update hash
    await supabaseAdmin.from('profiles').update({ password_hash: hash }).eq('id', existing.id);
  }
  
  console.log("2. Testing platform_login...");
  const { data: loginData, error: loginError } = await supabase.rpc('platform_login', {
    p_identifier: dummyIdentifier,
    p_password: dummyPassword
  });
  
  if (loginError || !loginData || !loginData.ok) {
    console.error("Login failed:", loginError || loginData);
    return;
  }
  
  const token = loginData.token;
  console.log("Logged in successfully. Session Token:", token);
  
  console.log("3. Verifying session exists in active_sessions table...");
  const { data: sessionsBefore } = await supabaseAdmin.from('active_sessions').select('*').eq('token', token);
  if (sessionsBefore && sessionsBefore.length > 0) {
    console.log("Session verified in database! Count:", sessionsBefore.length);
  } else {
    console.error("Session NOT found in database after login!");
  }
  
  console.log("4. Testing platform_logout...");
  const { error: logoutError } = await supabase.rpc('platform_logout', { p_token: token });
  if (logoutError) {
    console.error("Logout failed:", logoutError);
    return;
  }
  
  console.log("Logout RPC succeeded. Verifying session was deleted...");
  const { data: sessionsAfter } = await supabaseAdmin.from('active_sessions').select('*').eq('token', token);
  if (sessionsAfter && sessionsAfter.length === 0) {
    console.log("SUCCESS: Session was cleanly deleted from active_sessions table!");
  } else {
    console.error("FAILURE: Session still exists in the database!", sessionsAfter);
  }
  
  // Cleanup
  await supabaseAdmin.from('profiles').delete().eq('identifier', dummyIdentifier);
  console.log("Cleanup complete.");
}
run();
