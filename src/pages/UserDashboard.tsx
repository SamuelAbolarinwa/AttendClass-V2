import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";
import { useAuth } from "../contexts/AuthContext";
import { CheckInFlow } from "../components/CheckInFlow";
import { getWorkingDays, isCountableDay, calculateAttendanceStats } from "../utils/attendanceHelpers";
import { AttendanceHeatmap } from "../components/AttendanceHeatmap";
import * as faceapi from "@vladmandic/face-api";

export function UserDashboard() {
  const { account } = useAuth();
  const [loading, setLoading] = useState(true);
  const [logs, setLogs] = useState<any[]>([]);

  useEffect(() => {
    // Silently preload models in the background so they are ready by the time the user clicks "Check In"
    const MODEL_URL = "/models";
    Promise.all([
      faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
      faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
      faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
    ]).catch(err => console.warn("Failed to preload models silently:", err));
  }, []);

  const [stats, setStats] = useState({ present: 0, absent: 0, percentage: 0 });
  const [showCheckIn, setShowCheckIn] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [trackingStart, setTrackingStart] = useState<string>("");
  const [endDate, setEndDate] = useState<Date>(new Date());
  const [cancelledDays, setCancelledDays] = useState<Set<string>>(new Set());

  const fetchDashboardData = async () => {
    if (!account) return;
    setLoading(true);
    setError(null);

    try {
      // 1. Fetch user's profile to get tracking_start_date & created_at
      const { data: profileData, error: profileErr } = await supabase
        .from("profiles")
        .select("created_at, tracking_start_date")
        .eq("id", account.id)
        .single();
      if (profileErr) throw profileErr;

      // 2. Fetch global app_settings
      const { data: settingsData, error: settingsErr } = await supabase
        .from("app_settings")
        .select("tracking_period_end_date")
        .single();
      if (settingsErr) throw settingsErr;

      // 3. Fetch cancelled days
      const { data: cancelledData, error: cancelledErr } = await supabase
        .from("cancelled_days")
        .select("cancelled_date");
      if (cancelledErr) throw cancelledErr;

      const cancelledSet = new Set(cancelledData.map((d) => d.cancelled_date));

      // 4. Fetch attendance via RPC
      const { data: logsData, error: logsErr } = await supabase.rpc("platform_get_my_attendance", {
        p_token: account.token
      });
      if (logsErr) throw logsErr;
      
      const res = logsData as any;
      if (!res.ok) throw new Error(res.error || "Failed to fetch attendance logs");
      
      const userLogs = res.data || [];
      setLogs(userLogs);

      // 5. Calculate Stats
      const trackingStartStr = profileData.tracking_start_date || profileData.created_at.split("T")[0];
      const endDateObj = settingsData?.tracking_period_end_date ? new Date(settingsData.tracking_period_end_date) : new Date();
      
      setTrackingStart(trackingStartStr);
      setEndDate(endDateObj);
      setCancelledDays(cancelledSet);
      
      let presentCount = 0;
      let absentCount = 0;
      
      const today = new Date();
      const end = endDateObj < today ? endDateObj : today;

      // Count working days
      for (let d = new Date(trackingStartStr); d <= end; d.setDate(d.getDate() + 1)) {
        const dayStr = d.toISOString().split("T")[0];
        
        // Skip weekends
        const dayOfWeek = d.getDay();
        if (dayOfWeek === 0 || dayOfWeek === 6) continue;
        
        // Skip cancelled days
        if (!isCountableDay(dayStr, trackingStartStr, cancelledSet)) continue;

        // Check if present (match against verified_at)
        const wasPresent = userLogs.some((log: any) => log.verified_at.startsWith(dayStr));
        if (wasPresent) {
          presentCount++;
        } else {
          absentCount++;
        }
      }

      const totalCountable = presentCount + absentCount;
      const percentage = totalCountable > 0 ? (presentCount / totalCountable) * 100 : 0;

      setStats({
        present: presentCount,
        absent: absentCount,
        percentage
      });

    } catch (err: any) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [account]);

  return (
    <div className="user-dashboard">
      <div className="flex items-center" style={{ justifyContent: "space-between", marginBottom: "var(--space-6)" }}>
        <div>
          <h2 style={{ fontSize: "var(--text-2xl)", fontWeight: 700 }}>My Attendance</h2>
          <p className="text-muted">Overview of your classes and check-ins.</p>
        </div>
        <button 
          className="btn btn-primary btn-lg" 
          onClick={() => setShowCheckIn(true)}
        >
          Check In Now
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {/* KPI Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "var(--space-4)", marginBottom: "var(--space-8)" }}>
        <div className="card text-center" style={{ padding: "var(--space-6)" }}>
          <div className="text-muted text-sm mb-2" style={{ fontWeight: 600, textTransform: "uppercase" }}>Days Present</div>
          <div style={{ fontSize: "2.5rem", fontWeight: 700, color: "var(--color-primary-600)" }}>{loading ? "-" : stats.present}</div>
        </div>
        <div className="card text-center" style={{ padding: "var(--space-6)" }}>
          <div className="text-muted text-sm mb-2" style={{ fontWeight: 600, textTransform: "uppercase" }}>Days Absent</div>
          <div style={{ fontSize: "2.5rem", fontWeight: 700, color: "var(--color-error)" }}>{loading ? "-" : stats.absent}</div>
        </div>
        <div className="card text-center" style={{ padding: "var(--space-6)" }}>
          <div className="text-muted text-sm mb-2" style={{ fontWeight: 600, textTransform: "uppercase" }}>Attendance %</div>
          <div style={{ fontSize: "2.5rem", fontWeight: 700, color: "var(--color-text)" }}>{loading ? "-" : `${stats.percentage.toFixed(1)}%`}</div>
        </div>
      </div>

      {/* Heatmap */}
      {!loading && trackingStart && (
        <AttendanceHeatmap
          logs={logs}
          trackingStartDate={trackingStart}
          endDate={endDate}
          cancelledDays={cancelledDays}
        />
      )}

      {/* History Table */}
      <div className="card">
        <div className="card-header">
          <h3>Recent History</h3>
        </div>
        <div className="table-wrapper">
          {loading ? (
            <div className="table-empty"><span className="spinner" /></div>
          ) : logs.length === 0 ? (
            <div className="table-empty">No attendance records found.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {logs.slice(0, 50).map((log) => {
                  const d = new Date(log.verified_at);
                  return (
                    <tr key={log.id}>
                      <td>{d.toLocaleDateString()}</td>
                      <td>{d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
                      <td><span className="badge badge-neutral">{log.method}</span></td>
                      <td><span className="badge badge-success">Present</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Check-In Modal */}
      {showCheckIn && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 500 }}>
            <div className="modal-header">
              <h2>Secure Check-In</h2>
              <button className="modal-close" onClick={() => setShowCheckIn(false)}>×</button>
            </div>
            <div className="modal-body">
              <CheckInFlow 
                onClose={() => setShowCheckIn(false)}
                onSuccess={() => {
                  fetchDashboardData();
                }}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
