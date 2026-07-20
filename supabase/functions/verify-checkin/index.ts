import { serve } from "https://deno.land/std@0.177.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.3"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { session_token, ble_short_code, ble_token, rssi, face_similarity } = await req.json()
    
    // Validations
    if (!session_token || !ble_short_code || !ble_token) {
      return new Response(JSON.stringify({ error: "Missing required parameters" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 })
    }

    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    // Verify session
    const { data: sessData, error: sessErr } = await supabaseAdmin.rpc('platform_verify_session', {
      p_token: session_token
    });

    if (sessErr || !(sessData as any)?.valid) {
      return new Response(JSON.stringify({ error: "Invalid or expired session" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 401 })
    }
    const account_id = (sessData as any).account_id;

    // Fetch device (using service role bypasses the column-level select revoke)
    const { data: devData, error: devErr } = await supabaseAdmin
      .from('devices')
      .select('id, totp_secret_encrypted, rssi_threshold_dbm')
      .eq('ble_short_code', ble_short_code)
      .single();

    if (devErr || !devData) {
      return new Response(JSON.stringify({ error: "Device not found" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 404 })
    }

    const secretBase32 = devData.totp_secret_encrypted;
    if (!secretBase32) {
      return new Response(JSON.stringify({ error: "Device has no TOTP secret" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 })
    }

    // Verify TOTP
    const secretBytes = base32ToUint8Array(secretBase32);
    const currentWindow = Math.floor(Date.now() / 30000);
    
    // Check 3 windows (current, -1, +1) to allow for minor clock drift
    let matched = false;
    for (const w of [currentWindow, currentWindow - 1, currentWindow + 1]) {
      const expected = await generateTOTP(secretBytes, w);
      if (expected === ble_token) {
        matched = true;
        break;
      }
    }

    if (!matched) {
      return new Response(JSON.stringify({ error: "invalid_token" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 })
    }

    // Proximity Enforcement: only check AFTER token is verified
    if (typeof devData.rssi_threshold_dbm === 'number' && rssi < devData.rssi_threshold_dbm) {
      return new Response(JSON.stringify({ error: "out_of_range" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 })
    }

    // Success! Check if already logged today
    const today = new Date().toISOString().split('T')[0];
    const { data: existingLogs, error: logSearchErr } = await supabaseAdmin
      .from('attendance_logs')
      .select('verified_at')
      .eq('student_id', account_id)
      .gte('verified_at', `${today}T00:00:00Z`)
      .lte('verified_at', `${today}T23:59:59.999Z`)
      .limit(1);

    if (logSearchErr) {
      throw logSearchErr;
    }

    if (existingLogs && existingLogs.length > 0) {
      return new Response(JSON.stringify({ ok: true, already_logged_today: true, logged_at: existingLogs[0].verified_at }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
    }

    const { data: insertData, error: insertErr } = await supabaseAdmin
      .from('attendance_logs')
      .insert({
        student_id: account_id,
        method: 'face_ble_signed',
        rssi_dbm: rssi,
        totp_verified: true,
        face_similarity_score: face_similarity,
        verified_at: new Date().toISOString()
      })
      .select('verified_at')
      .single();

    if (insertErr) {
      throw insertErr;
    }

    return new Response(JSON.stringify({ ok: true, already_logged_today: false, logged_at: insertData.verified_at }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } })

  } catch (error: any) {
    console.error(error)
    return new Response(JSON.stringify({ error: error.message }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 })
  }
})

function base32ToUint8Array(base32: string) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor((base32.length * 5) / 8));
  for (let i = 0; i < base32.length; i++) {
    const val = alphabet.indexOf(base32[i].toUpperCase());
    if (val < 0) continue; 
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return output.slice(0, index);
}

async function generateTOTP(secretBytes: Uint8Array, window: number): Promise<string> {
  const timeBuffer = new ArrayBuffer(8);
  const timeView = new DataView(timeBuffer);
  // Big-endian 64-bit integer. Set the lower 32 bits (safe until 2106).
  timeView.setUint32(4, window, false);
  
  const key = await crypto.subtle.importKey(
    'raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, timeBuffer);
  const hmac = new Uint8Array(signature);
  
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
               ((hmac[offset + 1] & 0xff) << 16) |
               ((hmac[offset + 2] & 0xff) << 8) |
               (hmac[offset + 3] & 0xff);
               
  return (code % 1000000).toString().padStart(6, '0');
}
