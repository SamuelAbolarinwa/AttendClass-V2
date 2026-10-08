import { useState, useEffect } from "react";
import { supabase } from "../lib/supabase";
import { useAuth } from "../contexts/AuthContext";

export interface StudentDevice {
  id: string;
  student_id: string;
  device_name: string | null;
  platform: string | null;
  credential_id: string | null;
  algorithm: string | null;
  enrolled_at: string;
  revoked_at?: string | null;
}

interface Props {
  student: {
    id: string;
    full_name: string;
    matric_number: string | null;
  };
  onClose: (didChange: boolean) => void;
}

export function DeviceManagementModal({ student, onClose }: Props) {
  const { account } = useAuth();
  const [loading, setLoading] = useState(true);
  const [device, setDevice] = useState<StudentDevice | null>(null);
  const [activationCode, setActivationCode] = useState<string | null>(null);
  const [codeExpiresAt, setCodeExpiresAt] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revocationReason, setRevocationReason] = useState("Admin requested device replacement");
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);

  const fetchDevice = async () => {
    setLoading(true);
    setError(null);
    try {
      const { data, error: devErr } = await supabase
        .from("student_devices")
        .select("id, student_id, device_name, platform, credential_id, algorithm, enrolled_at, revoked_at")
        .eq("student_id", student.id)
        .is("revoked_at", null)
        .order("enrolled_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (devErr) throw devErr;
      setDevice(data ?? null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevice();
  }, [student.id]);

  const handleGenerateCode = async () => {
    if (!account) return;
    setGenerating(true);
    setError(null);
    setCopied(false);

    try {
      const { data, error: rpcErr } = await supabase.rpc("admin_generate_device_activation_code", {
        p_admin_token: account.token,
        p_student_id: student.id,
        p_expiry_minutes: 1440, // 24 hours validity
      });

      if (rpcErr) throw rpcErr;

      const res = data as { ok?: boolean; activation_code?: string; expires_at?: string; error?: string };
      if (!res.ok) {
        throw new Error(res.error || "Failed to generate activation code");
      }

      setActivationCode(res.activation_code || null);
      setCodeExpiresAt(res.expires_at || null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setGenerating(false);
    }
  };

  const handleRevokeDevice = async () => {
    if (!account || !device) return;
    setRevoking(true);
    setError(null);

    try {
      const { data, error: rpcErr } = await supabase.rpc("admin_revoke_device", {
        p_admin_token: account.token,
        p_device_id: device.id,
        p_reason: revocationReason || "Admin revoked",
      });

      if (rpcErr) throw rpcErr;

      const res = data as { ok?: boolean; error?: string };
      if (!res.ok) {
        throw new Error(res.error || "Failed to revoke device");
      }

      setShowRevokeConfirm(false);
      setDevice(null);
      await fetchDevice();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRevoking(false);
    }
  };

  const handleCopyCode = () => {
    if (!activationCode) return;
    navigator.clipboard.writeText(activationCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: 520 }}>
        <div className="modal-header">
          <h2>Manage Device — {student.full_name}</h2>
          <button className="modal-close" onClick={() => onClose(true)}>×</button>
        </div>

        <div className="modal-body">
          <p className="text-sm text-muted">
            Matric: <strong>{student.matric_number || "—"}</strong>
          </p>

          {error && (
            <div style={{ marginTop: 12, padding: "8px 12px", background: "#fee2e2", color: "#991b1b", borderRadius: 6, fontSize: 13 }}>
              {error}
            </div>
          )}

          <div style={{ marginTop: 16 }}>
            <h4 style={{ margin: "0 0 8px 0" }}>Active Enrolled Phone</h4>
            {loading ? (
              <p className="text-sm text-muted">Loading device details...</p>
            ) : device ? (
              <div style={{ background: "var(--color-bg)", padding: 12, borderRadius: 6, border: "1px solid var(--color-border)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontWeight: 600 }}>{device.device_name || "Enrolled Device"}</div>
                    <div className="text-sm text-muted" style={{ marginTop: 2 }}>
                      Platform: {device.platform || "Android"} • Algorithm: {device.algorithm || "ECDSA P-256"}
                    </div>
                    <div className="text-xs text-muted" style={{ marginTop: 2, fontFamily: "monospace" }}>
                      Cred ID: {device.credential_id || "Legacy"}
                    </div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>
                      Enrolled: {new Date(device.enrolled_at).toLocaleString()}
                    </div>
                  </div>
                  <span className="badge badge-success">Active</span>
                </div>

                <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
                  <button
                    className="btn btn-danger btn-sm"
                    disabled={revoking}
                    onClick={() => setShowRevokeConfirm(true)}
                  >
                    Revoke Device
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    disabled={generating}
                    onClick={handleGenerateCode}
                  >
                    {generating ? "Generating..." : "Issue Replacement Code"}
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ background: "var(--color-bg)", padding: 12, borderRadius: 6, border: "1px solid var(--color-border)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span className="text-sm text-muted">No phone currently enrolled for this student.</span>
                  <span className="badge badge-neutral">Not Enrolled</span>
                </div>
                <div style={{ marginTop: 12 }}>
                  <button
                    className="btn btn-primary btn-sm"
                    disabled={generating}
                    onClick={handleGenerateCode}
                  >
                    {generating ? "Generating..." : "Issue Activation Code"}
                  </button>
                </div>
              </div>
            )}
          </div>

          {activationCode && (
            <div style={{ marginTop: 20, padding: 16, background: "var(--color-bg)", borderRadius: 8, border: "2px solid #3b82f6", textAlign: "center" }}>
              <div className="text-xs text-muted" style={{ textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
                Single-Use Activation Code
              </div>
              <div style={{ margin: "10px 0", fontSize: "1.75rem", fontWeight: 700, letterSpacing: 6, fontFamily: "monospace", color: "#1e40af" }}>
                {activationCode}
              </div>
              {codeExpiresAt && (
                <div className="text-xs text-muted">
                  Expires: {new Date(codeExpiresAt).toLocaleString()}
                </div>
              )}
              <div style={{ marginTop: 12, display: "flex", justifyContent: "center", gap: 8 }}>
                <button className="btn btn-secondary btn-sm" onClick={handleCopyCode}>
                  {copied ? "Copied to Clipboard!" : "Copy Code"}
                </button>
              </div>
              <p className="text-xs text-muted mt-2">
                Provide this 8-character code to the student to enter in AttendClass during phone setup. It is single-use and rate-limited.
              </p>
            </div>
          )}

          {showRevokeConfirm && (
            <div style={{ marginTop: 16, padding: 12, background: "#fef2f2", border: "1px solid #f87171", borderRadius: 6 }}>
              <div style={{ fontWeight: 600, color: "#991b1b" }}>Confirm Device Revocation</div>
              <p className="text-xs text-muted mt-1">
                Revoking this device invalidates its hardware key. Attendance submissions from this device will be rejected.
              </p>
              <div style={{ marginTop: 8 }}>
                <label className="text-xs text-muted" style={{ display: "block", marginBottom: 4 }}>
                  Revocation Reason
                </label>
                <input
                  type="text"
                  className="input input-sm"
                  style={{ width: "100%" }}
                  value={revocationReason}
                  onChange={(e) => setRevocationReason(e.target.value)}
                />
              </div>
              <div style={{ marginTop: 10, display: "flex", gap: 8, justifyContent: "flex-end" }}>
                <button
                  className="btn btn-secondary btn-sm"
                  disabled={revoking}
                  onClick={() => setShowRevokeConfirm(false)}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-danger btn-sm"
                  disabled={revoking}
                  onClick={handleRevokeDevice}
                >
                  {revoking ? "Revoking..." : "Confirm Revoke"}
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-primary" onClick={() => onClose(true)}>Done</button>
        </div>
      </div>
    </div>
  );
}
