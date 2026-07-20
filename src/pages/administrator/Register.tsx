import { useEffect, useState } from "react";
import { supabase } from "../../lib/supabase";
import { useAuth } from "../../contexts/AuthContext";
import { getWorkingDays, isCountableDay, calculateAttendanceStats } from "../../utils/attendanceHelpers";

interface UserProfile {
  id: string;
  full_name: string;
  identifier: string;
  tracking_start_date: string | null;
  created_at: string;
}

export function Register() {
  const { account } = useAuth();
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [logs, setLogs] = useState<Record<string, Set<string>>>({}); // userId -> set of dates
  const [cancelledDays, setCancelledDays] = useState<Set<string>>(new Set());
  const [workingDays, setWorkingDays] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);

    // 1. Fetch Users
    const { data: usersData } = await supabase
      .from("profiles")
      .select("id, full_name, identifier, tracking_start_date, created_at")
      .eq("role", "user")
      .order("full_name");

    const fetchedUsers = (usersData || []) as UserProfile[];
    setUsers(fetchedUsers);

    // 2. Fetch Cancelled Days
    const { data: cancelledData } = await supabase.from("cancelled_days").select("cancelled_date");
    const cDays = new Set((cancelledData || []).map((c) => c.cancelled_date));
    setCancelledDays(cDays);

    // 3. Fetch Settings
    const { data: settingsData } = await supabase.from("app_settings").select("tracking_period_end_date").limit(1).single();
    let endDate = new Date().toISOString().split("T")[0];
    if (settingsData?.tracking_period_end_date) {
      endDate = settingsData.tracking_period_end_date;
      if (new Date(endDate) > new Date()) {
        endDate = new Date().toISOString().split("T")[0]; // Don't show future days beyond today
      }
    }

    // 4. Fetch Logs
    const { data: logsData } = await supabase.from("attendance_logs").select("student_id, verified_at");
    const logMap: Record<string, Set<string>> = {};
    if (logsData) {
      for (const log of logsData) {
        const dateStr = log.verified_at.split("T")[0];
        if (!logMap[log.student_id]) logMap[log.student_id] = new Set();
        logMap[log.student_id].add(dateStr);
      }
    }
    setLogs(logMap);

    // 5. Compute Matrix Range
    let minDate = endDate;
    for (const u of fetchedUsers) {
      const start = u.tracking_start_date || u.created_at.split("T")[0];
      if (start < minDate) minDate = start;
    }

    if (minDate > endDate) minDate = endDate; // sanity fallback
    setWorkingDays(getWorkingDays(minDate, endDate));
    setLoading(false);
  };

  const handleToggle = async (userId: string, dateStr: string, isCurrentlyPresent: boolean) => {
    if (toggling || !account) return;
    setToggling(true);

    const willBePresent = !isCurrentlyPresent;

    // Optimistic UI update
    setLogs((prev) => {
      const next = { ...prev };
      if (!next[userId]) next[userId] = new Set();
      const userSet = new Set(next[userId]);
      if (willBePresent) userSet.add(dateStr);
      else userSet.delete(dateStr);
      next[userId] = userSet;
      return next;
    });

    const { error } = await supabase.rpc("platform_toggle_attendance", {
      p_token: account.token,
      p_student_id: userId,
      p_date: dateStr,
      p_present: willBePresent,
    });

    if (error) {
      alert(`Failed to toggle attendance: ${error.message}`);
      fetchData(); // Revert on failure
    }
    setToggling(false);
  };

  const handleExportCSV = () => {
    let csv = "S/N,Student Name,Matric Number";
    for (const d of workingDays) {
      csv += `,${d}${cancelledDays.has(d) ? " (HOLIDAY)" : ""}`;
    }
    csv += ",Days Present,Days Absent,Attendance %\n";

    users.forEach((u, idx) => {
      let row = `${idx + 1},"${u.full_name}",${u.identifier}`;
      const userLogs = logs[u.id] || new Set();
      const userStart = u.tracking_start_date || u.created_at.split("T")[0];

      for (const d of workingDays) {
        if (cancelledDays.has(d)) row += ",—";
        else if (d < userStart) row += ",—";
        else if (userLogs.has(d)) row += ",✓";
        else row += ",✗";
      }

      const stats = calculateAttendanceStats(userStart, workingDays, cancelledDays, userLogs);
      row += `,${stats.present},${stats.absent},${stats.percentage.toFixed(1)}%\n`;
      csv += row;
    });

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `Attendance_Register_${new Date().toISOString().split("T")[0]}.csv`;
    link.click();
  };

  const handleExportXLSX = async () => {
    try {
      const ExcelJS = (await import("exceljs")).default;
      const { saveAs } = await import("file-saver");

      const wb = new ExcelJS.Workbook();
      const ws = wb.addWorksheet("Attendance Register", {
        views: [{ state: 'frozen', xSplit: 3, ySplit: 1 }]
      });

      const headerRow = ["S/N", "Student Name", "Matric Number"];
      for (const d of workingDays) {
        headerRow.push(`${d}${cancelledDays.has(d) ? " (HOLIDAY)" : ""}`);
      }
      headerRow.push("Days Present", "Days Absent", "Attendance %");
      
      const header = ws.addRow(headerRow);
      header.font = { bold: true };

      users.forEach((u, idx) => {
        const userLogs = logs[u.id] || new Set();
        const userStart = u.tracking_start_date || u.created_at.split("T")[0];
        
        const rowData: any[] = [idx + 1, u.full_name, u.identifier];
        for (const d of workingDays) {
          if (cancelledDays.has(d)) rowData.push("—");
          else if (d < userStart) rowData.push("—");
          else if (userLogs.has(d)) rowData.push("✓");
          else rowData.push("✗");
        }

        const stats = calculateAttendanceStats(userStart, workingDays, cancelledDays, userLogs);
        rowData.push(stats.present, stats.absent, `${stats.percentage.toFixed(1)}%`);
        ws.addRow(rowData);
      });

      const buffer = await wb.xlsx.writeBuffer();
      saveAs(new Blob([buffer]), `Attendance_Register_${new Date().toISOString().split("T")[0]}.xlsx`);
    } catch (e) {
      console.error(e);
      alert("Failed to export XLSX. Ensure exceljs and file-saver are installed via pnpm.");
    }
  };

  if (loading) return <div className="card"><span className="spinner" /> Loading Matrix...</div>;

  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>
      <div className="card-header" style={{ flexShrink: 0 }}>
        <div>
          <h3>Register Matrix</h3>
          <p className="text-sm text-muted mt-1">Click a cell to manually toggle attendance.</p>
        </div>
        <div style={{ display: "flex", gap: "var(--space-2)" }}>
          <button className="btn btn-secondary btn-sm" onClick={handleExportCSV}>Export CSV</button>
          <button className="btn btn-primary btn-sm" onClick={handleExportXLSX}>Export XLSX</button>
        </div>
      </div>

      <div style={{ flex: 1, overflow: "auto", borderTop: "1px solid var(--color-border)" }}>
        <table className="matrix-table" style={{ borderCollapse: "separate", borderSpacing: 0, width: "max-content", minWidth: "100%" }}>
          <thead>
            <tr>
              <th style={{ position: "sticky", left: 0, zIndex: 10, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderRight: "1px solid var(--color-border)", padding: "12px 16px" }}>S/N</th>
              <th style={{ position: "sticky", left: 50, zIndex: 10, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderRight: "1px solid var(--color-border)", padding: "12px 16px", minWidth: 200 }}>Name</th>
              <th style={{ position: "sticky", left: 250, zIndex: 10, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderRight: "2px solid var(--color-border)", padding: "12px 16px" }}>Identifier</th>
              {workingDays.map(d => (
                <th key={d} style={{ borderBottom: "1px solid var(--color-border)", borderRight: "1px solid var(--color-border)", padding: "8px", textAlign: "center", minWidth: 40 }}>
                  <div style={{ writingMode: "vertical-rl", transform: "rotate(180deg)", whiteSpace: "nowrap", fontSize: "11px", fontWeight: 500, color: cancelledDays.has(d) ? "var(--color-muted)" : "inherit" }}>
                    {d.slice(5)} {cancelledDays.has(d) && "(H)"}
                  </div>
                </th>
              ))}
              <th style={{ position: "sticky", right: 120, zIndex: 10, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderLeft: "2px solid var(--color-border)", padding: "12px 8px" }}>P</th>
              <th style={{ position: "sticky", right: 80, zIndex: 10, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", padding: "12px 8px" }}>A</th>
              <th style={{ position: "sticky", right: 0, zIndex: 10, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", padding: "12px 16px" }}>%</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u, idx) => {
              const userLogs = logs[u.id] || new Set();
              const userStart = u.tracking_start_date || u.created_at.split("T")[0];
              const stats = calculateAttendanceStats(userStart, workingDays, cancelledDays, userLogs);

              return (
                <tr key={u.id}>
                  <td style={{ position: "sticky", left: 0, zIndex: 5, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderRight: "1px solid var(--color-border)", padding: "8px 16px", color: "var(--color-muted)", fontSize: "13px" }}>{idx + 1}</td>
                  <td style={{ position: "sticky", left: 50, zIndex: 5, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderRight: "1px solid var(--color-border)", padding: "8px 16px", fontWeight: 500, fontSize: "14px" }}>{u.full_name}</td>
                  <td style={{ position: "sticky", left: 250, zIndex: 5, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderRight: "2px solid var(--color-border)", padding: "8px 16px" }}><code style={{ fontSize: "11px" }}>{u.identifier}</code></td>
                  
                  {workingDays.map(d => {
                    const isCancelled = cancelledDays.has(d);
                    const isPreStart = d < userStart;
                    const isPresent = userLogs.has(d);

                    let display = "✗";
                    let color = "var(--color-danger)";
                    let bg = "transparent";
                    let cursor = "pointer";

                    if (isCancelled) {
                      display = "—";
                      color = "var(--color-muted)";
                      bg = "var(--color-bg-muted)";
                      cursor = "not-allowed";
                    } else if (isPreStart) {
                      display = "—";
                      color = "rgba(255,255,255,0.1)";
                      cursor = "not-allowed";
                    } else if (isPresent) {
                      display = "✓";
                      color = "var(--color-success)";
                      bg = "rgba(16, 185, 129, 0.1)";
                    }

                    return (
                      <td 
                        key={d} 
                        style={{ borderBottom: "1px solid var(--color-border)", borderRight: "1px solid var(--color-border)", textAlign: "center", color, backgroundColor: bg, cursor, userSelect: "none" }}
                        onClick={() => {
                          if (!isCancelled && !isPreStart) handleToggle(u.id, d, isPresent);
                        }}
                      >
                        {display}
                      </td>
                    );
                  })}
                  
                  <td style={{ position: "sticky", right: 120, zIndex: 5, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", borderLeft: "2px solid var(--color-border)", padding: "8px", textAlign: "center", color: "var(--color-success)", fontWeight: 600 }}>{stats.present}</td>
                  <td style={{ position: "sticky", right: 80, zIndex: 5, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", padding: "8px", textAlign: "center", color: "var(--color-danger)", fontWeight: 600 }}>{stats.absent}</td>
                  <td style={{ position: "sticky", right: 0, zIndex: 5, background: "var(--color-bg)", borderBottom: "1px solid var(--color-border)", padding: "8px 16px", textAlign: "center", fontWeight: "bold" }}>
                    {stats.percentage.toFixed(1)}%
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
