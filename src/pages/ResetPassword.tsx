import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { supabase } from "../lib/supabase";

export function ResetPassword() {
  const { account, loading, updateAccount } = useAuth();
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (loading) {
    return (
      <div className="reset-page">
        <div className="spinner" style={{ width: 32, height: 32 }} />
      </div>
    );
  }

  if (!account) return <Navigate to="/login" replace />;

  if (!account.must_change_password) {
    const home = account.role === "administrator" ? "/administrator/students" :
                 account.role === "manager" ? "/manager/dashboard" :
                 "/dashboard";
    return <Navigate to={home} replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newPw.length < 8) { setError("New password must be at least 8 characters."); return; }
    if (newPw !== confirm) { setError("Passwords do not match."); return; }

    setSubmitting(true);

    const { data, error: rpcErr } = await supabase.rpc("platform_force_set_password", {
      p_token: account.token,
      p_current_password: currentPw,
      p_new_password: newPw,
    });

    if (rpcErr) { setError(rpcErr.message); setSubmitting(false); return; }

    const result = data as Record<string, unknown>;
    if (!result.ok) { setError((result.error as string) || "Failed"); setSubmitting(false); return; }

    // Check if user has an active face enrollment
    const { data: enrollData, error: enrollErr } = await supabase.rpc("platform_has_active_enrollment", {
      p_token: account.token,
    });

    updateAccount({ must_change_password: false });

    if (!enrollErr && enrollData && (enrollData as any).has_active === false) {
      window.location.href = "/enroll-face";
    } else {
      const home = account.role === "administrator" ? "/administrator/students" :
                   account.role === "manager" ? "/manager/dashboard" :
                   "/dashboard";
      window.location.href = home;
    }
  };

  return (
    <div className="reset-page">
      <div className="reset-card">
        <div className="warning-icon">🔐</div>
        <h1>Set Your Password</h1>
        <p className="subtitle">
          Your account was created with a temporary password.
          Please choose a new password before continuing.
        </p>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="reset-current">Current Password</label>
            <input
              id="reset-current"
              type="password"
              className="form-input"
              placeholder="Your temporary password"
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <label htmlFor="reset-new">New Password</label>
            <input
              id="reset-new"
              type="password"
              className="form-input"
              placeholder="At least 8 characters"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              required
              minLength={8}
            />
          </div>

          <div className="form-group">
            <label htmlFor="reset-confirm">Confirm New Password</label>
            <input
              id="reset-confirm"
              type="password"
              className="form-input"
              placeholder="Type it again"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
            />
          </div>

          <button type="submit" className="btn btn-primary btn-lg btn-block" disabled={submitting}>
            {submitting ? <><span className="spinner" /> Updating…</> : "Set Password & Continue"}
          </button>
        </form>
      </div>
    </div>
  );
}
