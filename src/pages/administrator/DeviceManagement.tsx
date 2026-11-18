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
  provisioned_version?: number | null;
  rssi_threshold_dbm?: number;
}

interface TerminalDetails {
  activeSession: {
    id: string;
    course_code: string;
    start_unix: number;
    end_unix: number;
  } | null;
  assignedSchedule: {
    course_code: string;
    day_name: string;
    time_slot: string;
  } | null;
  enrolledKeyCount: number;
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

interface AttendanceReviewItem {
  id: string;
  event_id: string;
  student_id: string;
  student_name?: string;
  matric_number?: string;
  terminal_id: string;
  terminal_name?: string;
  session_id?: string;
  terminal_saved_at: string | null;
  phone_attendance_time: string | null;
  server_received_at: string;
  time_source: "ntp" | "rtc" | "provisional_phone" | "unsynchronized" | "unknown";
  time_verification_status: "verified" | "pending_review" | "flagged_anomalous" | "rejected";
  clock_skew_seconds: number | null;
  reviewed_by?: string;
  reviewer_name?: string;
  reviewed_at?: string;
  review_notes?: string;
}

export function DeviceManagement() {
  const { account } = useAuth();
  const [activeTab, setActiveTab] = useState<"students" | "requests" | "terminals" | "audit" | "time_reviews">("students");
  const [students, setStudents] = useState<Student[]>([]);
  const [devicesMap, setDevicesMap] = useState<Record<string, StudentDevice>>({});
  const [changeRequests, setChangeRequests] = useState<ChangeRequest[]>([]);
  const [terminals, setTerminals] = useState<TerminalDevice[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [reviewQueue, setReviewQueue] = useState<AttendanceReviewItem[]>([]);
  const [reviewFilterStatus, setReviewFilterStatus] = useState<string>("all");
  const [reviewSearchQuery, setReviewSearchQuery] = useState<string>("");
  const [selectedRecordForReview, setSelectedRecordForReview] = useState<AttendanceReviewItem | null>(null);
  const [reviewDecision, setReviewDecision] = useState<"verified" | "rejected" | "flagged_anomalous">("verified");
  const [reviewNotes, setReviewNotes] = useState<string>("");
  const [submittingReview, setSubmittingReview] = useState<boolean>(false);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState<"all" | "enrolled" | "unenrolled">("all");
  const [selectedStudentForModal, setSelectedStudentForModal] = useState<Student | null>(null);
  const [actionMsg, setActionMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [selectedTerminalForQR, setSelectedTerminalForQR] = useState<TerminalDevice | null>(null);
  const [rejectModalReq, setRejectModalReq] = useState<ChangeRequest | null>(null);
  const [rejectReason, setRejectReason] = useState("Device replacement denied by lecturer/administrator.");
  const [approvingReqId, setApprovingReqId] = useState<string | null>(null);

  // Terminal Provisioning & Management States
  const [terminalDetailsMap, setTerminalDetailsMap] = useState<Record<string, TerminalDetails>>({});
  const [selectedTerminalForEditKey, setSelectedTerminalForEditKey] = useState<TerminalDevice | null>(null);
  const [newTerminalKey, setNewTerminalKey] = useState<string>("");
  const [submittingKey, setSubmittingKey] = useState<boolean>(false);
  const [selectedTerminalForBundle, setSelectedTerminalForBundle] = useState<TerminalDevice | null>(null);
  const [bundleLoading, setBundleLoading] = useState<boolean>(false);
  const [bundleData, setBundleData] = useState<any>(null);

  const fetchData = async () => {
    setLoading(true);
    setActionMsg(null);
    try {
      // 1. Fetch Students, Active Devices, Schedules & Active Sessions
      const [profilesRes, devicesRes, requestsRes, terminalsRes, schedulesRes, sessionsRes, enrollmentsRes] = await Promise.all([
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
          .select("id, device_id, name, location, public_key, algorithm, is_active, last_sync_at, provisioned_version, rssi_threshold_dbm")
          .order("device_id"),
        supabase
          .from("schedules")
          .select("id, course_id, device_id, day_of_week, start_time, end_time, courses(id, code, title)"),
        supabase
          .from("attendance_sessions")
          .select("id, schedule_id, device_id, opened_at, closed_at, schedules(id, course_id, device_id, start_time, end_time, courses(id, code, title))")
          .is("closed_at", null),
        supabase
          .from("enrollments")
          .select("student_id, course_id"),
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

      const terminalList = terminalsRes.data ?? [];
      setTerminals(terminalList);

      // Map Schedule, Active Session & Enrolled Student Count for each Terminal
      const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      const detailsMap: Record<string, TerminalDetails> = {};
      const allSchedules = schedulesRes.data ?? [];
      const allSessions = sessionsRes.data ?? [];
      const allEnrollments = enrollmentsRes.data ?? [];

      for (const t of terminalList) {
        // Find assigned schedule
        const sched: any = allSchedules.find((s: any) => s.device_id === t.id);
        let assignedSchedule = null;
        if (sched) {
          const dayName = DAYS[sched.day_of_week] || `Day ${sched.day_of_week}`;
          const timeSlot = `${(sched.start_time || "").slice(0, 5)} - ${(sched.end_time || "").slice(0, 5)}`;
          const schedCourse = Array.isArray(sched.courses) ? sched.courses[0] : sched.courses;
          assignedSchedule = {
            course_code: schedCourse?.code || "Unknown",
            day_name: dayName,
            time_slot: timeSlot,
          };
        }

        // Find open session
        const matchingSess: any = allSessions.find((s: any) => {
          const sSched = Array.isArray(s.schedules) ? s.schedules[0] : s.schedules;
          return s.device_id === t.id || sSched?.device_id === t.id;
        });
        let activeSession = null;
        let enrolledKeyCount = 0;

        if (matchingSess) {
          const sSched = Array.isArray(matchingSess.schedules) ? matchingSess.schedules[0] : matchingSess.schedules;
          const sCourse = Array.isArray(sSched?.courses) ? sSched?.courses[0] : sSched?.courses;
          const courseCode = sCourse?.code || "—";
          const courseId = sSched?.course_id;
          const startUnix = Math.floor(new Date(matchingSess.opened_at).getTime() / 1000);
          activeSession = {
            id: matchingSess.id,
            course_code: courseCode,
            start_unix: startUnix,
            end_unix: startUnix + 3600,
          };

          if (courseId) {
            const enrolledInCourse = allEnrollments.filter((e: any) => e.course_id === courseId);
            enrolledKeyCount = enrolledInCourse.filter((e: any) => !!dMap[e.student_id]).length;
          }
        }

        detailsMap[t.device_id] = {
          activeSession,
          assignedSchedule,
          enrolledKeyCount,
        };
      }
      setTerminalDetailsMap(detailsMap);

      // Fetch Audit Logs & Time Provenance Reviews
      if (account?.token) {
        const [auditRes, revRes] = await Promise.all([
          supabase.rpc("platform_get_device_audit_log", {
            p_admin_token: account.token,
            p_limit: 100,
          }),
          supabase.rpc("admin_get_pending_attendance_reviews", {
            p_token: account.token,
            p_status: "all",
            p_limit: 100,
          }),
        ]);
        if (auditRes.data?.ok) {
          setAuditLogs(auditRes.data.entries ?? []);
        }
        if (revRes.data?.ok) {
          setReviewQueue(revRes.data.records ?? []);
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

  // Submit Review for an Attendance Record
  const handleSubmitReview = async () => {
    if (!account || !selectedRecordForReview) return;
    setSubmittingReview(true);
    setActionMsg(null);
    try {
      const { data, error } = await supabase.rpc("admin_review_attendance_record", {
        p_token: account.token,
        p_event_id: selectedRecordForReview.event_id,
        p_decision: reviewDecision,
        p_notes: reviewNotes.trim() || null,
      });

      if (error) throw error;
      const res = data as any;
      if (!res.ok) throw new Error(res.error || "Review submission failed");

      setActionMsg({
        text: `Updated attendance record (${selectedRecordForReview.matric_number}): Status changed to ${reviewDecision.replace("_", " ").toUpperCase()}.`,
        type: "success",
      });
      setSelectedRecordForReview(null);
      setReviewNotes("");
      await fetchData();
    } catch (err: unknown) {
      setActionMsg({
        text: err instanceof Error ? err.message : String(err),
        type: "error",
      });
    } finally {
      setSubmittingReview(false);
    }
  };

  // Export Time Provenance Review Queue to CSV
  const handleExportReviewQueueCSV = () => {
    if (reviewQueue.length === 0) return;
    const headers = [
      "Event ID",
      "Matric Number",
      "Student Name",
      "Terminal ID",
      "Time Source",
      "Verification Status",
      "Terminal Recorded Time",
      "Phone Attendance Time",
      "Clock Skew (sec)",
      "Server Ingest Time",
      "Reviewer",
      "Reviewed At",
      "Notes",
    ];
    const rows = reviewQueue.map((r) => [
      r.event_id,
      r.matric_number || "",
      r.student_name || "",
      r.terminal_id,
      r.time_source,
      r.time_verification_status,
      r.terminal_saved_at || "",
      r.phone_attendance_time || "",
      r.clock_skew_seconds !== null ? String(r.clock_skew_seconds) : "",
      r.server_received_at,
      r.reviewer_name || "",
      r.reviewed_at || "",
      (r.review_notes || "").replace(/"/g, '""'),
    ]);
    const csvContent = [headers.join(","), ...rows.map((row) => row.map((cell) => `"${cell}"`).join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `attendance_time_reviews_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setActionMsg({
      text: "Exported attendance time review queue to CSV.",
      type: "success",
    });
  };

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
  const pendingTimeReviewsCount = reviewQueue.filter(
    (r) => r.time_verification_status === "pending_review" || r.time_verification_status === "flagged_anomalous"
  ).length;

  const filteredReviews = reviewQueue.filter((r) => {
    const q = reviewSearchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      (r.student_name && r.student_name.toLowerCase().includes(q)) ||
      (r.matric_number && r.matric_number.toLowerCase().includes(q)) ||
      (r.terminal_id && r.terminal_id.toLowerCase().includes(q)) ||
      (r.event_id && r.event_id.toLowerCase().includes(q));

    if (reviewFilterStatus !== "all" && r.time_verification_status !== reviewFilterStatus) {
      return false;
    }
    return matchesSearch;
  });

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

  const handleOpenEditKey = (terminal: TerminalDevice) => {
    setSelectedTerminalForEditKey(terminal);
    setNewTerminalKey(terminal.public_key || "");
  };

  const handleSaveTerminalKey = async () => {
    if (!account || !selectedTerminalForEditKey) return;
    setSubmittingKey(true);
    setActionMsg(null);
    try {
      const { data, error } = await supabase.rpc("platform_update_terminal_key", {
        p_admin_token: account.token,
        p_terminal_id: selectedTerminalForEditKey.device_id,
        p_public_key: newTerminalKey.trim(),
      });
      if (error) throw error;
      if (!data?.ok) throw new Error(data?.error || "Failed to update terminal public key");

      setActionMsg({
        text: `Terminal ${selectedTerminalForEditKey.device_id} public key updated successfully (v${data.provisioned_version}).`,
        type: "success",
      });
      setSelectedTerminalForEditKey(null);
      await fetchData();
    } catch (err: unknown) {
      setActionMsg({
        text: `Error registering terminal key: ${err instanceof Error ? err.message : String(err)}`,
        type: "error",
      });
    } finally {
      setSubmittingKey(false);
    }
  };

  const handleTriggerReprovision = async (terminal: TerminalDevice) => {
    if (!account) return;
    setActionMsg(null);
    try {
      const { data, error } = await supabase.rpc("platform_trigger_terminal_reprovision", {
        p_admin_token: account.token,
        p_terminal_id: terminal.device_id,
      });
      if (error) throw error;
      if (!data?.ok) throw new Error(data?.error || "Failed to trigger reprovisioning");

      setActionMsg({
        text: `Reprovisioning triggered for ${terminal.device_id}. Provisioned version incremented to v${data.provisioned_version}. The terminal will reload configuration on next sync.`,
        type: "success",
      });
      await fetchData();
    } catch (err: unknown) {
      setActionMsg({
        text: `Error triggering reprovision: ${err instanceof Error ? err.message : String(err)}`,
        type: "error",
      });
    }
  };

  const downloadJsonFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: "application/json;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const downloadCsvFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleOpenBundleModal = async (terminal: TerminalDevice) => {
    if (!account) return;
    setSelectedTerminalForBundle(terminal);
    setBundleLoading(true);
    setBundleData(null);
    try {
      const { data, error } = await supabase.rpc("platform_get_terminal_provisioning", {
        p_admin_token: account.token,
        p_terminal_id: terminal.device_id,
      });
      if (error) throw error;
      if (!data?.ok) throw new Error(data?.message || data?.error || "Failed to load provisioning bundle");
      setBundleData(data);
    } catch (err: unknown) {
      setActionMsg({
        text: `Error loading provisioning bundle: ${err instanceof Error ? err.message : String(err)}`,
        type: "error",
      });
      setSelectedTerminalForBundle(null);
    } finally {
      setBundleLoading(false);
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
        <div className="card" style={{ padding: 14 }}>
          <div className="text-xs text-muted">Pending Time Reviews</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4, color: pendingTimeReviewsCount > 0 ? "#d97706" : "inherit" }}>
            {pendingTimeReviewsCount}
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
        <button
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "time_reviews" ? "2px solid #2563eb" : "none",
            color: activeTab === "time_reviews" ? "#2563eb" : "var(--color-text-muted)",
            fontWeight: activeTab === "time_reviews" ? 600 : 500,
            cursor: "pointer",
          }}
          onClick={() => setActiveTab("time_reviews")}
        >
          ⏰ Time Reviews {pendingTimeReviewsCount > 0 ? `(${pendingTimeReviewsCount})` : ""}
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
          <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3 style={{ margin: "0 0 2px 0" }}>Provisioned Physical Terminals (ESP32)</h3>
              <p className="text-xs text-muted" style={{ margin: 0 }}>
                Classroom hardware terminals deployed in lecture halls with cryptographic keypairs, local registries, and authoritative session provisioning.
              </p>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-secondary btn-sm" onClick={handleDownloadProvisioningCSV}>
                📥 Global /enrolled_keys.csv
              </button>
            </div>
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
                    <th>Name / Room</th>
                    <th>Public Key</th>
                    <th>Assigned Timetable</th>
                    <th>Current Session</th>
                    <th>Enrolled Keys</th>
                    <th>Status / Version</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {terminals.map((t) => {
                    const details = terminalDetailsMap[t.device_id];
                    return (
                      <tr key={t.id}>
                        <td style={{ fontWeight: 600 }}>
                          <code style={{ fontSize: "var(--text-xs)", background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                            {t.device_id}
                          </code>
                        </td>
                        <td>
                          <div style={{ fontWeight: 500 }}>{t.name}</div>
                          <div className="text-xs text-muted">{t.location || "Unassigned"}</div>
                        </td>
                        <td>
                          {t.public_key ? (
                            <div>
                              <span className="badge badge-success" style={{ fontSize: 11, padding: "2px 6px" }}>P-256 Registered</span>
                              <div className="text-xs text-muted" style={{ fontFamily: "monospace", marginTop: 2 }}>
                                {t.public_key.slice(0, 16)}...
                              </div>
                            </div>
                          ) : (
                            <span className="badge badge-warning" style={{ fontSize: 11, padding: "2px 6px" }}>Key Pending</span>
                          )}
                        </td>
                        <td>
                          {details?.assignedSchedule ? (
                            <div>
                              <span style={{ fontWeight: 600 }}>{details.assignedSchedule.course_code}</span>
                              <div className="text-xs text-muted">
                                {details.assignedSchedule.day_name} • {details.assignedSchedule.time_slot}
                              </div>
                            </div>
                          ) : (
                            <span className="text-xs text-muted">Unscheduled</span>
                          )}
                        </td>
                        <td>
                          {details?.activeSession ? (
                            <div>
                              <span className="badge badge-success" style={{ fontSize: 11, padding: "2px 6px" }}>
                                Open: {details.activeSession.course_code}
                              </span>
                              <div className="text-xs text-muted" style={{ fontFamily: "monospace", marginTop: 2 }}>
                                {details.activeSession.id.slice(0, 8)}...
                              </div>
                            </div>
                          ) : (
                            <span className="badge badge-neutral" style={{ fontSize: 11, padding: "2px 6px", background: "var(--color-bg-subtle, #f1f5f9)", color: "var(--color-text-muted, #64748b)" }}>
                              No Open Session
                            </span>
                          )}
                        </td>
                        <td>
                          {details?.activeSession ? (
                            <div>
                              <span style={{ fontWeight: 600 }}>{details.enrolledKeyCount}</span>
                              <span className="text-xs text-muted"> active keys</span>
                            </div>
                          ) : (
                            <span className="text-xs text-muted">—</span>
                          )}
                        </td>
                        <td>
                          <div>
                            {t.is_active ? (
                              <span className="badge badge-success">Operational</span>
                            ) : (
                              <span className="badge badge-danger">Deactivated</span>
                            )}
                            <span className="text-xs text-muted" style={{ marginLeft: 6 }}>
                              v{t.provisioned_version || 1}
                            </span>
                          </div>
                          <div className="text-xs text-muted" style={{ marginTop: 2 }}>
                            {t.last_sync_at ? new Date(t.last_sync_at).toLocaleString() : "Never synced"}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            <button
                              className="btn btn-secondary btn-sm"
                              style={{ padding: "3px 7px", fontSize: 11 }}
                              title="Register or update terminal P-256 public key"
                              onClick={() => handleOpenEditKey(t)}
                            >
                              🔑 Key
                            </button>
                            <button
                              className="btn btn-secondary btn-sm"
                              style={{ padding: "3px 7px", fontSize: 11 }}
                              title="Trigger reprovisioning at next Wi-Fi connection"
                              onClick={() => handleTriggerReprovision(t)}
                            >
                              🔄 Reprovision
                            </button>
                            <button
                              className="btn btn-secondary btn-sm"
                              style={{ padding: "3px 7px", fontSize: 11 }}
                              title="Export SD Card provisioning bundle (/terminal_config.json + /enrolled_keys.csv)"
                              onClick={() => handleOpenBundleModal(t)}
                            >
                              📥 SD Bundle
                            </button>
                            <button
                              className="btn btn-secondary btn-sm"
                              style={{ padding: "3px 7px", fontSize: 11 }}
                              onClick={() => setSelectedTerminalForQR(t)}
                            >
                              QR
                            </button>
                          </div>
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

      {/* TAB 5: Time Provenance & Reviews */}
      {activeTab === "time_reviews" && (
        <div className="card">
          <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", flex: 1, minWidth: 260 }}>
              <input
                type="text"
                className="input input-sm"
                placeholder="Search by student name, matric, or terminal..."
                value={reviewSearchQuery}
                onChange={(e) => setReviewSearchQuery(e.target.value)}
                style={{ width: "100%", maxWidth: 360 }}
              />
              <select
                className="input input-sm"
                value={reviewFilterStatus}
                onChange={(e) => setReviewFilterStatus(e.target.value)}
                style={{ padding: "4px 8px" }}
              >
                <option value="all">All Verification Statuses</option>
                <option value="pending_review">Pending Review Only</option>
                <option value="flagged_anomalous">Anomalous / Out-of-Window</option>
                <option value="verified">Verified Only</option>
                <option value="rejected">Rejected Only</option>
              </select>
            </div>
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleExportReviewQueueCSV}
                disabled={reviewQueue.length === 0}
              >
                📥 Export Reviews CSV
              </button>
              <div className="text-xs text-muted">
                Showing {filteredReviews.length} of {reviewQueue.length} records
              </div>
            </div>
          </div>

          <div className="table-wrapper">
            {loading ? (
              <div className="table-empty"><span className="spinner" /></div>
            ) : filteredReviews.length === 0 ? (
              <div className="table-empty">
                <p>No attendance records match the selected review filter.</p>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Student</th>
                    <th>Terminal</th>
                    <th>Time Source</th>
                    <th>Status</th>
                    <th>Terminal Recorded Time</th>
                    <th>Phone Timestamp</th>
                    <th>Clock Skew</th>
                    <th>Cloud Ingested At</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredReviews.map((r) => {
                    const skewStr = r.clock_skew_seconds !== null
                      ? `${r.clock_skew_seconds}s (${Math.round(r.clock_skew_seconds / 60)}m)`
                      : "—";

                    return (
                      <tr key={r.id || r.event_id}>
                        <td>
                          <div style={{ fontWeight: 500 }}>{r.student_name || "Unknown Student"}</div>
                          <code style={{ fontSize: "var(--text-xs)", background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                            {r.matric_number || "—"}
                          </code>
                        </td>
                        <td>
                          <div style={{ fontWeight: 500 }}>{r.terminal_id}</div>
                          {r.terminal_name && <div className="text-xs text-muted">{r.terminal_name}</div>}
                        </td>
                        <td>
                          {r.time_source === "ntp" ? (
                            <span className="badge badge-success">🟢 NTP Attested</span>
                          ) : r.time_source === "rtc" ? (
                            <span className="badge badge-neutral">🔵 Hardware RTC</span>
                          ) : r.time_source === "provisional_phone" ? (
                            <span className="badge badge-warning">🟡 Provisional Phone</span>
                          ) : r.time_source === "unsynchronized" ? (
                            <span className="badge badge-neutral">⚪ Unsynchronized</span>
                          ) : (
                            <span className="badge badge-neutral" style={{ background: "#fed7aa", color: "#9a3412" }}>
                              🟠 Unknown (Unsigned)
                            </span>
                          )}
                        </td>
                        <td>
                          {r.time_verification_status === "verified" ? (
                            <span className="badge badge-success">Verified</span>
                          ) : r.time_verification_status === "flagged_anomalous" ? (
                            <span className="badge badge-danger">⚠️ Anomalous Skew</span>
                          ) : r.time_verification_status === "rejected" ? (
                            <span className="badge badge-danger">Rejected</span>
                          ) : (
                            <span className="badge badge-warning">Pending Review</span>
                          )}
                        </td>
                        <td className="text-xs" style={{ whiteSpace: "nowrap" }}>
                          {r.terminal_saved_at ? new Date(r.terminal_saved_at).toLocaleString() : "—"}
                        </td>
                        <td className="text-xs text-muted" style={{ whiteSpace: "nowrap" }}>
                          {r.phone_attendance_time ? new Date(r.phone_attendance_time).toLocaleString() : "—"}
                        </td>
                        <td className="text-xs">
                          {r.clock_skew_seconds !== null && r.clock_skew_seconds > 900 ? (
                            <span style={{ color: "#dc2626", fontWeight: 600 }}>{skewStr}</span>
                          ) : (
                            <span>{skewStr}</span>
                          )}
                        </td>
                        <td className="text-xs text-muted" style={{ whiteSpace: "nowrap" }}>
                          {r.server_received_at ? new Date(r.server_received_at).toLocaleTimeString() : "—"}
                        </td>
                        <td>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => {
                              setSelectedRecordForReview(r);
                              setReviewDecision(
                                r.time_verification_status === "rejected"
                                  ? "rejected"
                                  : r.time_verification_status === "flagged_anomalous"
                                  ? "flagged_anomalous"
                                  : "verified"
                              );
                              setReviewNotes(r.review_notes || "");
                            }}
                          >
                            Review
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

      {/* Review Provisional Attendance Record Modal */}
      {selectedRecordForReview && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 520 }}>
            <div className="modal-header">
              <h3 style={{ margin: 0 }}>Review Provisional Attendance Record</h3>
              <button className="modal-close" onClick={() => setSelectedRecordForReview(null)}>×</button>
            </div>
            <div className="modal-body">
              <div style={{ background: "var(--color-bg)", padding: 12, borderRadius: 6, marginBottom: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span className="text-xs text-muted">Student:</span>
                  <span style={{ fontWeight: 600 }}>{selectedRecordForReview.student_name} ({selectedRecordForReview.matric_number})</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span className="text-xs text-muted">Terminal ID:</span>
                  <code>{selectedRecordForReview.terminal_id}</code>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span className="text-xs text-muted">Time Source:</span>
                  <span>{selectedRecordForReview.time_source}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span className="text-xs text-muted">Terminal Recorded Time:</span>
                  <span className="text-xs">{selectedRecordForReview.terminal_saved_at || "—"}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span className="text-xs text-muted">Phone Submitted Time:</span>
                  <span className="text-xs">{selectedRecordForReview.phone_attendance_time || "—"}</span>
                </div>
                {selectedRecordForReview.clock_skew_seconds !== null && (
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span className="text-xs text-muted">Clock Skew:</span>
                    <span style={{ color: selectedRecordForReview.clock_skew_seconds > 900 ? "#dc2626" : "inherit", fontWeight: 600 }}>
                      {selectedRecordForReview.clock_skew_seconds} seconds
                    </span>
                  </div>
                )}
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span className="text-xs text-muted">Server Ingest Time:</span>
                  <span className="text-xs text-muted">{selectedRecordForReview.server_received_at}</span>
                </div>
              </div>

              <div>
                <label className="text-xs text-muted" style={{ display: "block", marginBottom: 6, fontWeight: 600 }}>
                  Verification Decision
                </label>
                <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
                  <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", fontSize: 13 }}>
                    <input
                      type="radio"
                      name="decision"
                      value="verified"
                      checked={reviewDecision === "verified"}
                      onChange={() => setReviewDecision("verified")}
                    />
                    <span>Verify (Approved)</span>
                  </label>
                  <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", fontSize: 13 }}>
                    <input
                      type="radio"
                      name="decision"
                      value="flagged_anomalous"
                      checked={reviewDecision === "flagged_anomalous"}
                      onChange={() => setReviewDecision("flagged_anomalous")}
                    />
                    <span>Flag Anomalous</span>
                  </label>
                  <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", fontSize: 13 }}>
                    <input
                      type="radio"
                      name="decision"
                      value="rejected"
                      checked={reviewDecision === "rejected"}
                      onChange={() => setReviewDecision("rejected")}
                    />
                    <span>Reject</span>
                  </label>
                </div>

                <label className="text-xs text-muted" style={{ display: "block", marginBottom: 4 }}>
                  Review Notes / Justification
                </label>
                <textarea
                  className="input input-sm"
                  rows={3}
                  style={{ width: "100%", resize: "vertical" }}
                  placeholder="e.g. Verified by lecturer against sign-in sheet, or out-of-window phone time."
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedRecordForReview(null)}
                disabled={submittingReview}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary btn-sm"
                onClick={handleSubmitReview}
                disabled={submittingReview}
              >
                {submittingReview ? "Saving..." : "Save Review Decision"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Register / Update Terminal Public Key */}
      {selectedTerminalForEditKey && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 540 }}>
            <div className="modal-header">
              <h3 style={{ margin: 0 }}>Register Terminal Public Key</h3>
              <button
                className="modal-close"
                onClick={() => setSelectedTerminalForEditKey(null)}
                disabled={submittingKey}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 13, fontWeight: 600 }}>Terminal: {selectedTerminalForEditKey.device_id} ({selectedTerminalForEditKey.name})</div>
                <div className="text-xs text-muted">Location: {selectedTerminalForEditKey.location || "Unassigned"}</div>
              </div>

              <div style={{ background: "var(--color-bg)", padding: 12, borderRadius: 6, marginBottom: 14, fontSize: 12, lineHeight: 1.5 }}>
                ℹ️ <strong>Security Requirement:</strong> Only authorized administrators can register or update the physical terminal's NIST P-256 public key. The terminal signs challenge packets, durable check-in receipts, and time-provenance statements using the private key stored securely in its firmware/NVS.
              </div>

              {selectedTerminalForEditKey.public_key && (
                <div style={{ marginBottom: 12 }}>
                  <label className="text-xs text-muted" style={{ display: "block", marginBottom: 2 }}>Current Registered Key (SPKI Base64)</label>
                  <pre style={{ fontSize: 11, background: "var(--color-bg)", padding: 8, borderRadius: 4, overflowX: "auto", margin: 0, wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
                    {selectedTerminalForEditKey.public_key}
                  </pre>
                </div>
              )}

              <div style={{ marginBottom: 14 }}>
                <label className="text-xs text-muted" style={{ display: "block", marginBottom: 4 }}>
                  NIST P-256 SPKI Public Key (Base64) *
                </label>
                <textarea
                  className="input input-sm"
                  rows={4}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 12, resize: "vertical" }}
                  placeholder="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
                  value={newTerminalKey}
                  onChange={(e) => setNewTerminalKey(e.target.value)}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedTerminalForEditKey(null)}
                disabled={submittingKey}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary btn-sm"
                onClick={handleSaveTerminalKey}
                disabled={submittingKey || !newTerminalKey.trim()}
              >
                {submittingKey ? "Saving..." : "Register & Bind Public Key"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Export SD Card Provisioning Bundle */}
      {selectedTerminalForBundle && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 600 }}>
            <div className="modal-header">
              <h3 style={{ margin: 0 }}>SD Provisioning Bundle — {selectedTerminalForBundle.device_id}</h3>
              <button
                className="modal-close"
                onClick={() => setSelectedTerminalForBundle(null)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              {bundleLoading ? (
                <div style={{ textAlign: "center", padding: 24 }}>Loading provisioning bundle from server...</div>
              ) : bundleData ? (
                <div>
                  <div style={{ background: "var(--color-bg)", padding: 12, borderRadius: 6, marginBottom: 14, fontSize: 12 }}>
                    💾 <strong>Offline Boot Instructions:</strong> Copy <code>/terminal_config.json</code> and <code>/enrolled_keys.csv</code> to the root of the terminal's MicroSD card before powering on in an offline lecture hall.
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14 }}>
                    <div style={{ background: "var(--color-bg)", padding: 10, borderRadius: 6 }}>
                      <div className="text-xs text-muted">Provisioning Version</div>
                      <div style={{ fontWeight: 700, fontSize: 16 }}>v{bundleData.provisioned_version}</div>
                    </div>
                    <div style={{ background: "var(--color-bg)", padding: 10, borderRadius: 6 }}>
                      <div className="text-xs text-muted">Active Session</div>
                      <div style={{ fontWeight: 700, fontSize: 14 }}>
                        {bundleData.active_session ? bundleData.active_session.course_code : "None (Closed)"}
                      </div>
                    </div>
                  </div>

                  {bundleData.active_session ? (
                    <div style={{ marginBottom: 14 }}>
                      <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Active Session Details:</div>
                      <pre style={{ fontSize: 11, background: "var(--color-bg)", padding: 8, borderRadius: 4, margin: 0 }}>
                        {JSON.stringify(bundleData.active_session, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <div style={{ background: "#fef3c7", color: "#92400e", padding: 10, borderRadius: 6, fontSize: 12, marginBottom: 14 }}>
                      ⚠️ <strong>No Active Session:</strong> No class is currently open for this terminal. The exported <code>/terminal_config.json</code> will have <code>active_session: null</code> and the ESP32 will withhold biometric attendance until a session is opened.
                    </div>
                  )}

                  <div style={{ marginBottom: 14 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                      <span className="text-xs text-muted">Enrolled Student Keys ({bundleData.enrolled_keys?.length || 0}):</span>
                    </div>
                    {bundleData.enrolled_keys?.length === 0 ? (
                      <div className="text-xs text-muted">No students currently enrolled for this session.</div>
                    ) : (
                      <div style={{ maxHeight: 120, overflowY: "auto", background: "var(--color-bg)", padding: 8, borderRadius: 4 }}>
                        {bundleData.enrolled_keys?.slice(0, 10).map((k: any) => (
                          <div key={k.student_id} className="text-xs" style={{ display: "flex", justifyContent: "space-between", padding: "2px 0" }}>
                            <span>{k.matric_number || k.student_id.slice(0, 8)}</span>
                            <code style={{ fontSize: 10 }}>{k.credential_id ? k.credential_id.slice(0, 16) : k.public_key.slice(0, 16)}...</code>
                          </div>
                        ))}
                        {bundleData.enrolled_keys?.length > 10 && (
                          <div className="text-xs text-muted" style={{ textAlign: "center", paddingTop: 4 }}>
                            + {bundleData.enrolled_keys.length - 10} more students
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
                    <button
                      className="btn btn-secondary btn-sm"
                      style={{ flex: 1 }}
                      onClick={() => {
                        const configJson = JSON.stringify({
                          terminal_id: bundleData.terminal_id,
                          provisioning_version: bundleData.provisioned_version,
                          active_session: bundleData.active_session,
                        }, null, 2);
                        downloadJsonFile(`terminal_config_${bundleData.terminal_id}.json`, configJson);
                      }}
                    >
                      📥 Download /terminal_config.json
                    </button>
                    <button
                      className="btn btn-secondary btn-sm"
                      style={{ flex: 1 }}
                      onClick={() => {
                        let csvText = "student_id,matric_number,public_key,credential_id,algorithm\n";
                        for (const k of (bundleData.enrolled_keys || [])) {
                          csvText += `${k.student_id},${k.matric_number},${k.public_key},${k.credential_id},${k.algorithm}\n`;
                        }
                        downloadCsvFile(`enrolled_keys_${bundleData.terminal_id}.csv`, csvText);
                      }}
                    >
                      📥 Download /enrolled_keys.csv
                    </button>
                  </div>
                </div>
              ) : (
                <div>Failed to load bundle data.</div>
              )}
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-primary btn-sm"
                onClick={() => setSelectedTerminalForBundle(null)}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
