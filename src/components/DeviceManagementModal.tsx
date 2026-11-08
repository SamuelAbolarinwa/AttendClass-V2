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
  revocation_reason?: string | null;
}

export interface AuditEntry {
  id: string;
  event_type: string;
  created_at: string;
  performed_by?: string;
  performer_name?: string;
  details?: Record<string, any>;
}

interface Props {
  student: {
    id: string;
    full_name: string;
    matric_number: string | null;
    identifier?: string;
  };
  onClose: (didChange: boolean) => void;
}

export function DeviceManagementModal({ student, onClose }: Props) {
  const { account } = useAuth();
  const [loading, setLoading] = useState(true);
  const [device, setDevice] = useState<StudentDevice | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [activationCode, setActivationCode] = useState<string | null>(null);
  const [codeExpiresAt, setCodeExpiresAt] = useState<string | null>(null);
  const [codePurpose, setCodePurpose] = useState<string>("device_enrollment");
  const [expiryMinutes, setExpiryMinutes] = useState<number>(60);
  const [generating, setGenerating] = useState(false);
  const [expiring, setExpiring] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [revocationReason, setRevocationReason] = useState("Admin requested device replacement");
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);
  const [activeTab, setActiveTab] = useState<"device" | "audit">("device");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch active device
      const { data: devData, error: devErr } = await supabase
        .from("student_devices")
        .select("id, student_id, device_name, platform, credential_id, algorithm, enrolled_at, revoked_at, revocation_reason")
        .eq("student_id", student.id)
        .is("revoked_at", null)
        .order("enrolled_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (devErr) throw devErr;
      setDevice(devData ?? null);

      // 2. Fetch device audit log if account token available
      if (account?.token) {
        const { data: auditData, error: auditErr } = await supabase.rpc("platform_get_device_audit_log", {
          p_admin_token: account.token,
          p_student_id: student.id,
          p_limit: 20,
        });

        if (!auditErr && auditData?.ok) {
          setAuditLogs(auditData.entries ?? []);
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [student.id]);

  const handleGenerateCode = async (purpose = "device_enrollment") => {
    if (!account) return;
    setGenerating(true);
    setError(null);
    setSuccessMsg(null);
    setCopied(false);

    try {
      const { data, error: rpcErr } = await supabase.rpc("admin_generate_device_activation_code", {
        p_admin_token: account.token,
        p_student_id: student.id,
        p_expiry_minutes: expiryMinutes,
        p_purpose: purpose,
      });

      if (rpcErr) throw rpcErr;

      const res = data as {
        ok?: boolean;
        activation_code?: string;
        expires_at?: string;
        purpose?: string;
        error?: string;
      };

      if (!res.ok) {
        throw new Error(res.error || "Failed to generate activation code");
      }

      setActivationCode(res.activation_code || null);
      setCodeExpiresAt(res.expires_at || null);
      setCodePurpose(res.purpose || purpose);
      setSuccessMsg("Activation code successfully generated.");
      await fetchData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setGenerating(false);
    }
  };

  const handleExpirePriorCodes = async () => {
    if (!account) return;
    setExpiring(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const { data, error: rpcErr } = await supabase.rpc("admin_expire_activation_code", {
        p_admin_token: account.token,
        p_student_id: student.id,
      });

      if (rpcErr) throw rpcErr;

      const res = data as { ok?: boolean; invalidated_count?: number; error?: string };
      if (!res.ok) {
        throw new Error(res.error || "Failed to expire activation codes");
      }

      setActivationCode(null);
      setCodeExpiresAt(null);
      setSuccessMsg(`Invalidated ${res.invalidated_count ?? 0} unredeemed activation code(s).`);
      await fetchData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExpiring(false);
    }
  };

  const handleRevokeDevice = async () => {
    if (!account || !device) return;
    setRevoking(true);
    setError(null);
    setSuccessMsg(null);

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
      setSuccessMsg("Device successfully revoked. Changes scheduled for offline terminal sync.");
      await fetchData();
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
      <div className="modal" style={{ maxWidth: 640 }}>
        <div className="modal-header">
          <div>
            <h2 style={{ margin: 0 }}>Manage Phone — {student.full_name}</h2>
            <div className="text-xs text-muted" style={{ marginTop: 4 }}>
              Matric: <strong>{student.matric_number || "—"}</strong>
              {student.identifier ? ` • ${student.identifier}` : ""}
            </div>
          </div>
          <button className="modal-close" onClick={() => onClose(true)}>×</button>
        </div>

        {/* Tab switch */}
        <div style={{ display: "flex", borderBottom: "1px solid var(--color-border)", padding: "0 16px" }}>
          <button
            style={{
              padding: "10px 16px",
              background: "none",
              border: "none",
              borderBottom: activeTab === "device" ? "2px solid #2563eb" : "none",
              color: activeTab === "device" ? "#2563eb" : "var(--color-text-muted)",
              fontWeight: activeTab === "device" ? 600 : 400,
              cursor: "pointer",
            }}
            onClick={() => setActiveTab("device")}
          >
            Device Status & Issuance
          </button>
          <button
            style={{
              padding: "10px 16px",
              background: "none",
              border: "none",
              borderBottom: activeTab === "audit" ? "2px solid #2563eb" : "none",
              color: activeTab === "audit" ? "#2563eb" : "var(--color-text-muted)",
              fontWeight: activeTab === "audit" ? 600 : 400,
              cursor: "pointer",
            }}
            onClick={() => setActiveTab("audit")}
          >
            Audit History ({auditLogs.length})
          </button>
        </div>

        <div className="modal-body">
          {error && (
            <div style={{ padding: "10px 14px", background: "#fee2e2", color: "#991b1b", borderRadius: 6, fontSize: 13, marginBottom: 14 }}>
              <strong>Error:</strong> {error}
            </div>
          )}

          {successMsg && (
            <div style={{ padding: "10px 14px", background: "#dcfce7", color: "#166534", borderRadius: 6, fontSize: 13, marginBottom: 14 }}>
              {successMsg}
            </div>
          )}

          {activeTab === "device" ? (
            <>
              <div>
                <h4 style={{ margin: "0 0 10px 0" }}>Active Enrolled Phone</h4>
                {loading ? (
                  <p className="text-sm text-muted">Loading device details...</p>
                ) : device ? (
                  <div style={{ background: "var(--color-bg)", padding: 14, borderRadius: 6, border: "1px solid var(--color-border)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 15 }}>{device.device_name || "Enrolled Phone"}</div>
                        <div className="text-sm text-muted" style={{ marginTop: 2 }}>
                          Platform: <strong>{device.platform || "Android"}</strong> • Algorithm: <strong>{device.algorithm || "ECDSA P-256"}</strong>
                        </div>
                        <div className="text-xs text-muted" style={{ marginTop: 4, fontFamily: "monospace", wordBreak: "break-all" }}>
                          Credential ID: {device.credential_id || "Legacy"}
                        </div>
                        <div className="text-xs text-muted" style={{ marginTop: 4 }}>
                          Enrolled: {new Date(device.enrolled_at).toLocaleString()}
                        </div>
                      </div>
                      <span className="badge badge-success">Active Enrolled</span>
                    </div>

                    <div style={{ marginTop: 14, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
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
                        onClick={() => handleGenerateCode("device_replacement")}
                      >
                        {generating ? "Generating..." : "Issue Replacement Code"}
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={expiring}
                        onClick={handleExpirePriorCodes}
                        title="Invalidates any outstanding unredeemed codes"
                      >
                        {expiring ? "Expiring..." : "Expire Pending Codes"}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div style={{ background: "var(--color-bg)", padding: 14, borderRadius: 6, border: "1px solid var(--color-border)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <div style={{ fontWeight: 500 }}>No phone currently registered</div>
                        <div className="text-xs text-muted" style={{ marginTop: 2 }}>
                          Issue an 8-character activation code to let this student enrol their hardware-backed phone.
                        </div>
                      </div>
                      <span className="badge badge-neutral">Not Enrolled</span>
                    </div>

                    <div style={{ marginTop: 14, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <label className="text-xs text-muted">Expiry:</label>
                        <select
                          className="input input-sm"
                          style={{ padding: "4px 8px" }}
                          value={expiryMinutes}
                          onChange={(e) => setExpiryMinutes(Number(e.target.value))}
                        >
                          <option value={15}>15 Minutes</option>
                          <option value={60}>60 Minutes (Default)</option>
                          <option value={1440}>24 Hours</option>
                        </select>
                      </div>
                      <button
                        className="btn btn-primary btn-sm"
                        disabled={generating}
                        onClick={() => handleGenerateCode("device_enrollment")}
                      >
                        {generating ? "Generating..." : "Generate Activation Code"}
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={expiring}
                        onClick={handleExpirePriorCodes}
                      >
                        {expiring ? "Expiring..." : "Expire Codes"}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Single-Use Activation Code Card */}
              {activationCode && (
                <div style={{ marginTop: 18, padding: 16, background: "var(--color-bg)", borderRadius: 8, border: "2px solid #2563eb", textAlign: "center" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span className="badge badge-primary text-xs" style={{ textTransform: "uppercase" }}>
                      {codePurpose === "device_replacement" ? "Replacement Code" : "Initial Activation Code"}
                    </span>
                    {codeExpiresAt && (
                      <span className="text-xs text-muted">
                        Expires: {new Date(codeExpiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} ({Math.round((new Date(codeExpiresAt).getTime() - Date.now()) / 60000)}m left)
                      </span>
                    )}
                  </div>

                  <div style={{ margin: "12px 0", fontSize: "2rem", fontWeight: 700, letterSpacing: 8, fontFamily: "monospace", color: "#1d4ed8" }}>
                    {activationCode}
                  </div>

                  <div style={{ display: "flex", justifyContent: "center", gap: 10 }}>
                    <button className="btn btn-primary btn-sm" onClick={handleCopyCode}>
                      {copied ? "✓ Copied to Clipboard!" : "Copy Code"}
                    </button>
                  </div>

                  <p className="text-xs text-muted mt-2" style={{ margin: "8px 0 0 0" }}>
                    Provide this exactly 8-character code to the student. They will navigate to: <strong>Settings & Device → Admin Activation Code</strong> on their mobile phone.
                    It is single-use, rate-limited to 3 attempts, and valid only for this account.
                  </p>
                </div>
              )}

              {/* Confirm Revoke Box */}
              {showRevokeConfirm && (
                <div style={{ marginTop: 16, padding: 14, background: "#fef2f2", border: "1px solid #f87171", borderRadius: 6 }}>
                  <div style={{ fontWeight: 600, color: "#991b1b" }}>Confirm Phone Revocation</div>
                  <p className="text-xs text-muted mt-1">
                    Revoking this phone permanently invalidates its hardware signing key. The student will NOT be able to mark offline attendance until an administrator issues a new replacement code.
                  </p>
                  <div style={{ marginTop: 10 }}>
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
                  <div style={{ marginTop: 12, display: "flex", gap: 8, justifyContent: "flex-end" }}>
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
                      {revoking ? "Revoking..." : "Confirm & Schedule Revocation"}
                    </button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div>
              <h4 style={{ margin: "0 0 10px 0" }}>Device & Credential Audit Trail</h4>
              {auditLogs.length === 0 ? (
                <p className="text-sm text-muted">No audit events recorded for this member yet.</p>
              ) : (
                <div className="table-wrapper" style={{ maxHeight: 280, overflowY: "auto" }}>
                  <table style={{ fontSize: 13 }}>
                    <thead>
                      <tr>
                        <th>Event</th>
                        <th>Performer</th>
                        <th>Time</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.map((log) => (
                        <tr key={log.id}>
                          <td>
                            <code style={{ fontSize: 11, background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                              {log.event_type}
                            </code>
                          </td>
                          <td>{log.performer_name || "System"}</td>
                          <td className="text-xs text-muted">{new Date(log.created_at).toLocaleString()}</td>
                          <td className="text-xs" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {JSON.stringify(log.details || {})}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
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
