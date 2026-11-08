import { useState, useEffect } from "react";
import { supabase } from "../../lib/supabase";
import { useAuth } from "../../contexts/AuthContext";
import { DeviceManagementModal, StudentDevice } from "../../components/DeviceManagementModal";

interface Student {
  id: string;
  full_name: string;
  matric_number: string | null;
  identifier?: string;
  must_change_password: boolean;
  created_at: string;
}

interface ChangeRequest {
  id: string;
  student_id: string;
  student_name?: string;
  matric_number?: string;
  reason: string;
  status: "pending" | "approved" | "rejected" | "completed";
  created_at: string;
  reviewed_at?: string;
  admin_notes?: string;
}

interface TerminalDevice {
  id: string;
  device_id: string;
  name: string;
  location: string | null;
  public_key?: string | null;
  algorithm?: string;
  is_active: boolean;
  last_sync_at?: string | null;
  rssi_threshold_dbm?: number;
}

interface AuditLog {
  id: string;
  event_type: string;
  student_id?: string;
  student_name?: string;
  matric_number?: string;
  performed_by?: string;
  performer_name?: string;
  details: Record<string, any>;
  created_at: string;
}

export function DeviceManagement() {
  const { account } = useAuth();
  const [activeTab, setActiveTab] = useState<"students" | "requests" | "terminals" | "audit">("students");
  const [students, setStudents] = useState<Student[]>([]);
  const [devicesMap, setDevicesMap] = useState<Record<string, StudentDevice>>({});
  const [changeRequests, setChangeRequests] = useState<ChangeRequest[]>([]);
  const [terminals, setTerminals] = useState<TerminalDevice[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState<"all" | "enrolled" | "unenrolled">("all");
  const [selectedStudentForModal, setSelectedStudentForModal] = useState<Student | null>(null);
  const [actionMsg, setActionMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [selectedTerminalForQR, setSelectedTerminalForQR] = useState<TerminalDevice | null>(null);
  const [rejectModalReq, setRejectModalReq] = useState<ChangeRequest | null>(null);
  const [rejectReason, setRejectReason] = useState("Device replacement denied by lecturer/administrator.");
  const [approvingReqId, setApprovingReqId] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setActionMsg(null);
    try {
      // 1. Fetch Students & Active Devices
      const [profilesRes, devicesRes, requestsRes, terminalsRes] = await Promise.all([
        supabase
          .from("profiles")
          .select("id, full_name, matric_number, identifier, must_change_password, created_at")
          .eq("role", "user")
          .order("full_name"),
        supabase
          .from("student_devices")
          .select("id, student_id, device_name, platform, credential_id, algorithm, enrolled_at, revoked_at")
          .is("revoked_at", null),
        supabase
          .from("device_change_requests")
          .select("id, student_id, reason, status, created_at, reviewed_at, admin_notes")
          .order("created_at", { ascending: false }),
        supabase
          .from("devices")
          .select("id, device_id, name, location, public_key, algorithm, is_active, last_sync_at, rssi_threshold_dbm")
          .order("device_id"),
      ]);

      const studentList = profilesRes.data ?? [];
      setStudents(studentList);

      const dMap: Record<string, StudentDevice> = {};
      if (devicesRes.data) {
        for (const d of devicesRes.data) {
          dMap[d.student_id] = d as StudentDevice;
        }
      }
      setDevicesMap(dMap);

      // Enhance requests with student details
      const studentLookup = new Map(studentList.map((s) => [s.id, s]));
      const reqList: ChangeRequest[] = (requestsRes.data ?? []).map((r: any) => ({
        ...r,
        student_name: studentLookup.get(r.student_id)?.full_name || "Unknown",
        matric_number: studentLookup.get(r.student_id)?.matric_number || "—",
      }));
      setChangeRequests(reqList);

      setTerminals(terminalsRes.data ?? []);

      // Fetch Audit Logs
      if (account?.token) {
        const { data: auditRes } = await supabase.rpc("platform_get_device_audit_log", {
          p_admin_token: account.token,
          p_limit: 100,
        });
        if (auditRes?.ok) {
          setAuditLogs(auditRes.entries ?? []);
        }
      }
    } catch (err: unknown) {
      console.error("Error fetching device management data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter students
  const filteredStudents = students.filter((s) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      s.full_name.toLowerCase().includes(q) ||
      (s.matric_number && s.matric_number.toLowerCase().includes(q)) ||
      (s.identifier && s.identifier.toLowerCase().includes(q));

    const isEnrolled = !!devicesMap[s.id];
    if (filterStatus === "enrolled" && !isEnrolled) return false;
    if (filterStatus === "unenrolled" && isEnrolled) return false;
    return matchesSearch;
  });

  const pendingRequests = changeRequests.filter((r) => r.status === "pending");

  // Approve Change Request
  const handleApproveRequest = async (req: ChangeRequest) => {
    if (!account) return;
    setApprovingReqId(req.id);
    setActionMsg(null);
    try {
      const { data, error } = await supabase.rpc("admin_approve_device_change", {
        p_admin_token: account.token,
        p_request_id: req.id,
        p_notes: "Approved by administrator. Replacement code issued with 24h validity.",
      });

      if (error) throw error;
      const res = data as any;
      if (!res.ok) throw new Error(res.error || "Approval failed");

      setActionMsg({
        text: `Approved request for ${req.student_name}. Replacement activation code: ${res.activation_code} (Valid for 24h).`,
        type: "success",
      });
      await fetchData();
    } catch (err: unknown) {
      setActionMsg({
        text: err instanceof Error ? err.message : String(err),
        type: "error",
      });
    } finally {
      setApprovingReqId(null);
    }
  };

  // Reject Change Request
  const handleRejectRequest = async () => {
    if (!account || !rejectModalReq) return;
    setActionMsg(null);
    try {
      const { data, error } = await supabase.rpc("admin_reject_device_change", {
        p_admin_token: account.token,
        p_request_id: rejectModalReq.id,
        p_reason: rejectReason,
      });

      if (error) throw error;
      const res = data as any;
      if (!res.ok) throw new Error(res.error || "Rejection failed");

      setActionMsg({
        text: `Rejected device change request for ${rejectModalReq.student_name}.`,
        type: "success",
      });
      setRejectModalReq(null);
      await fetchData();
    } catch (err: unknown) {
      setActionMsg({
        text: err instanceof Error ? err.message : String(err),
        type: "error",
      });
    }
  };

  // Download Provisioning CSV
  const handleDownloadProvisioningCSV = async () => {
    if (!account) return;
    try {
      const { data, error } = await supabase.rpc("platform_get_enrolled_keys_csv", {
        p_admin_token: account.token,
      });

      if (error) throw error;
      const csvText = data as string;
      const blob = new Blob([csvText], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `enrolled_keys_${new Date().toISOString().slice(0, 10)}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      setActionMsg({
        text: "Downloaded enrolled keys provisioning CSV for ESP32 SD card (/enrolled_keys.csv).",
        type: "success",
      });
    } catch (err: unknown) {
      setActionMsg({
        text: `Failed to download CSV: ${err instanceof Error ? err.message : String(err)}`,
        type: "error",
      });
    }
  };

  return (
    <div style={{ maxWidth: 1200, margin: "0 auto", paddingBottom: 40 }}>
      {/* Page Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: "0 0 4px 0" }}>Device & Terminal Management</h2>
          <p className="text-sm text-muted" style={{ margin: 0 }}>
            Authoritative portal for student phone enrolment, offline ESP32 terminal provisioning, and sync audits.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={fetchData} disabled={loading}>
            {loading ? "Refreshing..." : "↻ Refresh"}
          </button>
          <button className="btn btn-primary btn-sm" onClick={handleDownloadProvisioningCSV}>
            📥 Download /enrolled_keys.csv
          </button>
        </div>
      </div>

      {/* Metrics Banner */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 20 }}>
        <div className="card" style={{ padding: 14 }}>
          <div className="text-xs text-muted">Total Registered Students</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4 }}>{students.length}</div>
        </div>
        <div className="card" style={{ padding: 14 }}>
          <div className="text-xs text-muted">Active Enrolled Phones</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4, color: "#16a34a" }}>
            {Object.keys(devicesMap).length}
          </div>
        </div>
        <div className="card" style={{ padding: 14 }}>
          <div className="text-xs text-muted">Unenrolled Students</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4, color: "#d97706" }}>
            {Math.max(0, students.length - Object.keys(devicesMap).length)}
          </div>
        </div>
        <div className="card" style={{ padding: 14 }}>
          <div className="text-xs text-muted">Pending Replacement Requests</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4, color: pendingRequests.length > 0 ? "#dc2626" : "inherit" }}>
            {pendingRequests.length}
          </div>
        </div>
      </div>

      {actionMsg && (
        <div
          style={{
            padding: "12px 16px",
            borderRadius: 6,
            marginBottom: 16,
            background: actionMsg.type === "success" ? "#dcfce7" : "#fee2e2",
            color: actionMsg.type === "success" ? "#166534" : "#991b1b",
            fontSize: 14,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>{actionMsg.text}</span>
          <button
            onClick={() => setActionMsg(null)}
            style={{ background: "none", border: "none", cursor: "pointer", fontSize: 16, color: "inherit" }}
          >
            ×
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--color-border)", marginBottom: 18, gap: 4 }}>
        <button
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "students" ? "2px solid #2563eb" : "none",
            color: activeTab === "students" ? "#2563eb" : "var(--color-text-muted)",
            fontWeight: activeTab === "students" ? 600 : 500,
            cursor: "pointer",
          }}
          onClick={() => setActiveTab("students")}
        >
          👥 Student Phones ({students.length})
        </button>
        <button
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "requests" ? "2px solid #2563eb" : "none",
            color: activeTab === "requests" ? "#2563eb" : "var(--color-text-muted)",
            fontWeight: activeTab === "requests" ? 600 : 500,
            cursor: "pointer",
          }}
          onClick={() => setActiveTab("requests")}
        >
          🔄 Replacement Requests {pendingRequests.length > 0 ? `(${pendingRequests.length})` : ""}
        </button>
        <button
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "terminals" ? "2px solid #2563eb" : "none",
            color: activeTab === "terminals" ? "#2563eb" : "var(--color-text-muted)",
            fontWeight: activeTab === "terminals" ? 600 : 500,
            cursor: "pointer",
          }}
          onClick={() => setActiveTab("terminals")}
        >
          📡 ESP32 Terminals ({terminals.length})
        </button>
        <button
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "audit" ? "2px solid #2563eb" : "none",
            color: activeTab === "audit" ? "#2563eb" : "var(--color-text-muted)",
            fontWeight: activeTab === "audit" ? 600 : 500,
            cursor: "pointer",
          }}
          onClick={() => setActiveTab("audit")}
        >
          📜 Audit History ({auditLogs.length})
        </button>
      </div>

      {/* TAB 1: Student Devices */}
      {activeTab === "students" && (
        <div className="card">
          <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", flex: 1, minWidth: 260 }}>
              <input
                type="text"
                className="input input-sm"
                placeholder="Search by name, matric number, or email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ width: "100%", maxWidth: 360 }}
              />
              <select
                className="input input-sm"
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value as any)}
                style={{ padding: "4px 8px" }}
              >
                <option value="all">All Statuses</option>
                <option value="enrolled">Enrolled Only</option>
                <option value="unenrolled">Unenrolled Only</option>
              </select>
            </div>
            <div className="text-xs text-muted">
              Showing {filteredStudents.length} of {students.length} students
            </div>
          </div>

          <div className="table-wrapper">
            {loading ? (
              <div className="table-empty"><span className="spinner" /></div>
            ) : filteredStudents.length === 0 ? (
              <div className="table-empty">
                <p>No students match the selected search or filter.</p>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Student Name</th>
                    <th>Matric Number</th>
                    <th>Enrolment Status</th>
                    <th>Device Details</th>
                    <th>Enrolled At</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredStudents.map((s) => {
                    const dev = devicesMap[s.id];
                    return (
                      <tr key={s.id}>
                        <td style={{ fontWeight: 500 }}>
                          <div>{s.full_name}</div>
                          <div className="text-xs text-muted">{s.identifier || "—"}</div>
                        </td>
                        <td>
                          <code style={{ fontSize: "var(--text-xs)", background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                            {s.matric_number || "—"}
                          </code>
                        </td>
                        <td>
                          {dev ? (
                            <span className="badge badge-success">Enrolled Phone</span>
                          ) : (
                            <span className="badge badge-neutral">Not Enrolled</span>
                          )}
                        </td>
                        <td>
                          {dev ? (
                            <div>
                              <div style={{ fontWeight: 500 }}>{dev.device_name || "Mobile Phone"}</div>
                              <div className="text-xs text-muted" style={{ fontFamily: "monospace" }}>
                                {dev.credential_id ? `ID: ${dev.credential_id.slice(0, 16)}...` : "ECDSA P-256"}
                              </div>
                            </div>
                          ) : (
                            <span className="text-xs text-muted">Awaiting Activation</span>
                          )}
                        </td>
                        <td className="text-xs text-muted">
                          {dev ? new Date(dev.enrolled_at).toLocaleDateString() : "—"}
                        </td>
                        <td>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => setSelectedStudentForModal(s)}
                          >
                            Manage Device
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Device Change Requests */}
      {activeTab === "requests" && (
        <div className="card">
          <div className="card-header">
            <div>
              <h3 style={{ margin: "0 0 2px 0" }}>Device Replacement Requests</h3>
              <p className="text-xs text-muted" style={{ margin: 0 }}>
                Enforces the one-phone-per-student policy. Students must request approval before enrolling a replacement phone.
              </p>
            </div>
          </div>

          <div className="table-wrapper">
            {changeRequests.length === 0 ? (
              <div className="table-empty">
                <p>No device replacement requests on record.</p>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Student</th>
                    <th>Matric Number</th>
                    <th>Stated Reason</th>
                    <th>Status</th>
                    <th>Submitted</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {changeRequests.map((req) => (
                    <tr key={req.id}>
                      <td style={{ fontWeight: 500 }}>{req.student_name}</td>
                      <td>
                        <code style={{ fontSize: "var(--text-xs)", background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                          {req.matric_number}
                        </code>
                      </td>
                      <td style={{ maxWidth: 300 }}>{req.reason}</td>
                      <td>
                        {req.status === "pending" && <span className="badge badge-warning">Pending Review</span>}
                        {req.status === "approved" && <span className="badge badge-success">Approved</span>}
                        {req.status === "rejected" && <span className="badge badge-danger">Rejected</span>}
                        {req.status === "completed" && <span className="badge badge-neutral">Completed</span>}
                      </td>
                      <td className="text-xs text-muted">{new Date(req.created_at).toLocaleString()}</td>
                      <td>
                        {req.status === "pending" ? (
                          <div style={{ display: "flex", gap: 6 }}>
                            <button
                              className="btn btn-primary btn-sm"
                              disabled={approvingReqId === req.id}
                              onClick={() => handleApproveRequest(req)}
                            >
                              {approvingReqId === req.id ? "Approving..." : "Approve & Issue Code"}
                            </button>
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => setRejectModalReq(req)}
                            >
                              Reject
                            </button>
                          </div>
                        ) : (
                          <span className="text-xs text-muted">{req.admin_notes || "—"}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: ESP32 Terminals & Provisioning */}
      {activeTab === "terminals" && (
        <div className="card">
          <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <h3 style={{ margin: "0 0 2px 0" }}>Provisioned Physical Terminals (ESP32)</h3>
              <p className="text-xs text-muted" style={{ margin: 0 }}>
                Classroom hardware terminals deployed in lecture halls with cryptographic keypairs and local SD registries.
              </p>
            </div>
            <button className="btn btn-secondary btn-sm" onClick={handleDownloadProvisioningCSV}>
              📥 Export Provisioning File
            </button>
          </div>

          <div className="table-wrapper">
            {terminals.length === 0 ? (
              <div className="table-empty">
                <p>No physical terminals registered yet.</p>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Terminal ID</th>
                    <th>Name / Location</th>
                    <th>Public Key Fingerprint</th>
                    <th>Status</th>
                    <th>Last Synchronized</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {terminals.map((t) => (
                    <tr key={t.id}>
                      <td style={{ fontWeight: 600 }}>
                        <code style={{ fontSize: "var(--text-xs)", background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                          {t.device_id}
                        </code>
                      </td>
                      <td>
                        <div>{t.name}</div>
                        <div className="text-xs text-muted">{t.location || "Unassigned"}</div>
                      </td>
                      <td className="text-xs" style={{ fontFamily: "monospace" }}>
                        {t.public_key ? `${t.public_key.slice(0, 20)}...` : "Configured on Terminal SD"}
                      </td>
                      <td>
                        {t.is_active ? (
                          <span className="badge badge-success">Operational</span>
                        ) : (
                          <span className="badge badge-danger">Deactivated</span>
                        )}
                      </td>
                      <td className="text-xs text-muted">
                        {t.last_sync_at ? new Date(t.last_sync_at).toLocaleString() : "Never"}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => setSelectedTerminalForQR(t)}
                        >
                          Printable QR
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: Audit History */}
      {activeTab === "audit" && (
        <div className="card">
          <div className="card-header">
            <div>
              <h3 style={{ margin: "0 0 2px 0" }}>System Device & Activation Audit Trail</h3>
              <p className="text-xs text-muted" style={{ margin: 0 }}>
                Immutable audit record of all code issuances, expirations, hardware registrations, replacements, and revocations.
              </p>
            </div>
          </div>

          <div className="table-wrapper">
            {auditLogs.length === 0 ? (
              <div className="table-empty">
                <p>No audit events recorded yet.</p>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Student</th>
                    <th>Matric Number</th>
                    <th>Performed By</th>
                    <th>Audit Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id}>
                      <td className="text-xs text-muted" style={{ whiteSpace: "nowrap" }}>
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td>
                        <code style={{ fontSize: 11, background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                          {log.event_type}
                        </code>
                      </td>
                      <td style={{ fontWeight: 500 }}>{log.student_name || "—"}</td>
                      <td>
                        <code style={{ fontSize: "var(--text-xs)", background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                          {log.matric_number || "—"}
                        </code>
                      </td>
                      <td>{log.performer_name || "System"}</td>
                      <td className="text-xs" style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {JSON.stringify(log.details || {})}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Device Management Modal for a selected student */}
      {selectedStudentForModal && (
        <DeviceManagementModal
          student={selectedStudentForModal}
          onClose={(didChange) => {
            setSelectedStudentForModal(null);
            if (didChange) fetchData();
          }}
        />
      )}

      {/* Terminal QR Modal */}
      {selectedTerminalForQR && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 480, textAlign: "center" }}>
            <div className="modal-header">
              <h3 style={{ margin: 0 }}>Terminal Static Identity QR</h3>
              <button className="modal-close" onClick={() => setSelectedTerminalForQR(null)}>×</button>
            </div>
            <div className="modal-body" style={{ padding: 20 }}>
              <p className="text-xs text-muted">
                This permanent QR code identifies physical terminal <strong>{selectedTerminalForQR.device_id}</strong>.
                Attach this static sticker to the physical terminal chassis.
              </p>

              <div
                style={{
                  margin: "16px auto",
                  padding: 16,
                  background: "#fff",
                  border: "2px dashed #2563eb",
                  borderRadius: 8,
                  display: "inline-block",
                  color: "#000",
                }}
              >
                <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>
                  ATTENDCLASS TERMINAL
                </div>
                <div style={{ padding: 12, background: "#f8fafc", borderRadius: 6, fontFamily: "monospace", fontSize: 11, textAlign: "left", wordBreak: "break-all" }}>
                  {JSON.stringify({
                    v: 1,
                    type: "ATTENDCLASS_TERMINAL",
                    terminal_id: selectedTerminalForQR.device_id,
                    name: selectedTerminalForQR.name,
                    location: selectedTerminalForQR.location || "Unassigned",
                    institution: "AttendClass-V2",
                  }, null, 2)}
                </div>
                <div style={{ fontSize: 11, color: "#64748b", marginTop: 8 }}>
                  Scan in mobile app during classroom check-in
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "center", gap: 10, marginTop: 10 }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    navigator.clipboard.writeText(
                      JSON.stringify({
                        v: 1,
                        type: "ATTENDCLASS_TERMINAL",
                        terminal_id: selectedTerminalForQR.device_id,
                      })
                    );
                    alert("Copied terminal payload to clipboard");
                  }}
                >
                  Copy Payload
                </button>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => window.print()}
                >
                  🖨 Print QR Sticker
                </button>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelectedTerminalForQR(null)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Reject Request Modal */}
      {rejectModalReq && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 440 }}>
            <div className="modal-header">
              <h3 style={{ margin: 0 }}>Reject Replacement Request</h3>
              <button className="modal-close" onClick={() => setRejectModalReq(null)}>×</button>
            </div>
            <div className="modal-body">
              <p className="text-sm">
                Rejecting replacement request for <strong>{rejectModalReq.student_name}</strong> ({rejectModalReq.matric_number}).
              </p>
              <div style={{ marginTop: 12 }}>
                <label className="text-xs text-muted" style={{ display: "block", marginBottom: 4 }}>
                  Reason for Rejection
                </label>
                <input
                  type="text"
                  className="input input-sm"
                  style={{ width: "100%" }}
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary btn-sm" onClick={() => setRejectModalReq(null)}>
                Cancel
              </button>
              <button className="btn btn-danger btn-sm" onClick={handleRejectRequest}>
                Confirm Rejection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
