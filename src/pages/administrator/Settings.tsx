import { useEffect, useState } from "react";
import { supabase } from "../../lib/supabase";
import { useAuth } from "../../contexts/AuthContext";

export function Settings() {
  const { account } = useAuth();
  
  // Settings State
  const [endDate, setEndDate] = useState("");
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsMsg, setSettingsMsg] = useState("");

  // Security State
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [savingSecurity, setSavingSecurity] = useState(false);
  const [securityMsg, setSecurityMsg] = useState("");
  const [securityErr, setSecurityErr] = useState("");

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    setLoadingSettings(true);
    const { data } = await supabase.from("app_settings").select("tracking_period_end_date").limit(1).single();
    if (data?.tracking_period_end_date) setEndDate(data.tracking_period_end_date);
    setLoadingSettings(false);
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!account) return;
    setSavingSettings(true);
    setSettingsMsg("");

    const val = endDate.trim() || null;
    const { error } = await supabase.rpc("platform_update_settings", {
      p_token: account.token,
      p_tracking_period_end_date: val
    });

    if (error) setSettingsMsg(`Error: ${error.message}`);
    else setSettingsMsg("Settings saved successfully.");
    
    setSavingSettings(false);
  };

  const handleUpdatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!account) return;
    setSecurityErr("");
    setSecurityMsg("");

    if (newPw.length < 8) { setSecurityErr("New password must be at least 8 characters."); return; }
    if (newPw !== confirmPw) { setSecurityErr("New passwords do not match."); return; }

    setSavingSecurity(true);
    const { data, error: rpcErr } = await supabase.rpc("platform_change_password", {
      p_token: account.token,
      p_current_password: currentPw,
      p_new_password: newPw,
    });

    if (rpcErr) { setSecurityErr(rpcErr.message); setSavingSecurity(false); return; }

    const res = data as Record<string, unknown>;
    if (!res.ok) { setSecurityErr((res.error as string) || "Failed"); setSavingSecurity(false); return; }

    setSecurityMsg("Password updated successfully.");
    setCurrentPw(""); setNewPw(""); setConfirmPw("");
    setSavingSecurity(false);
  };

  return (
    <div style={{ maxWidth: 640, margin: "0 auto", display: "flex", flexDirection: "column", gap: 24 }}>
      
      {/* Global Settings */}
      <div className="card">
        <div className="card-header">
          <h3>Global Settings</h3>
        </div>
        <div className="card-body">
          {loadingSettings ? (
            <div className="spinner" />
          ) : (
            <form onSubmit={handleSaveSettings}>
              <div className="form-group">
                <label>Tracking Period End Date</label>
                <p className="text-sm text-muted mb-2">
                  If set, attendance percentage calculations will stop at this date, even if today is later. Leave blank to always track up to today.
                </p>
                <input 
                  type="date" 
                  className="form-input" 
                  value={endDate} 
                  onChange={(e) => setEndDate(e.target.value)} 
                />
              </div>
              
              {settingsMsg && (
                <div className={`alert ${settingsMsg.includes("Error") ? "alert-error" : "alert-success"} mb-4`}>
                  {settingsMsg}
                </div>
              )}

              <button type="submit" className="btn btn-primary" disabled={savingSettings}>
                {savingSettings ? <><span className="spinner" /> Saving...</> : "Save Settings"}
              </button>
            </form>
          )}
        </div>
      </div>

      {/* Security */}
      <div className="card">
        <div className="card-header">
          <h3>Security</h3>
        </div>
        <div className="card-body">
          <form onSubmit={handleUpdatePassword}>
            <div className="form-group">
              <label>Current Password</label>
              <input type="password" className="form-input" value={currentPw} onChange={e => setCurrentPw(e.target.value)} required />
            </div>
            <div className="form-group">
              <label>New Password</label>
              <input type="password" className="form-input" value={newPw} onChange={e => setNewPw(e.target.value)} required minLength={8} />
            </div>
            <div className="form-group">
              <label>Confirm New Password</label>
              <input type="password" className="form-input" value={confirmPw} onChange={e => setConfirmPw(e.target.value)} required />
            </div>

            {securityErr && <div className="alert alert-error mb-4">{securityErr}</div>}
            {securityMsg && <div className="alert alert-success mb-4">{securityMsg}</div>}

            <button type="submit" className="btn btn-secondary" disabled={savingSecurity}>
              {savingSecurity ? <><span className="spinner" /> Updating...</> : "Update Password"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
