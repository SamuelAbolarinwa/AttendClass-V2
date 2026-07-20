import { useEffect, useState, useMemo } from "react";
import { supabase } from "../../lib/supabase";
import { getWorkingDays, calculateAttendanceStats } from "../../utils/attendanceHelpers";

interface UserProfile {
  id: string;
  full_name: string;
  identifier: string;
  tracking_start_date: string | null;
  created_at: string;
}

export function Statistics() {
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [logs, setLogs] = useState<Record<string, Set<string>>>({});
  const [cancelledDays, setCancelledDays] = useState<Set<string>>(new Set());
  const [workingDays, setWorkingDays] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  // Sorting state
  const [sortKey, setSortKey] = useState<"name" | "present" | "absent" | "percentage">("percentage");
  const [sortAsc, setSortAsc] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);

    const { data: usersData } = await supabase.from("profiles").select("*").eq("role", "user");
    const fetchedUsers = (usersData || []) as UserProfile[];
    setUsers(fetchedUsers);

    const { data: cancelledData } = await supabase.from("cancelled_days").select("cancelled_date");
    const cDays = new Set((cancelledData || []).map((c) => c.cancelled_date));
    setCancelledDays(cDays);

    const { data: settingsData } = await supabase.from("app_settings").select("tracking_period_end_date").limit(1).single();
    let endDate = new Date().toISOString().split("T")[0];
    if (settingsData?.tracking_period_end_date && new Date(settingsData.tracking_period_end_date) <= new Date()) {
      endDate = settingsData.tracking_period_end_date;
    }

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

    let minDate = endDate;
    for (const u of fetchedUsers) {
      const start = u.tracking_start_date || u.created_at.split("T")[0];
      if (start < minDate) minDate = start;
    }

    if (minDate > endDate) minDate = endDate;
    setWorkingDays(getWorkingDays(minDate, endDate));
    setLoading(false);
  };

  const statsList = useMemo(() => {
    return users.map(u => {
      const userLogs = logs[u.id] || new Set();
      const userStart = u.tracking_start_date || u.created_at.split("T")[0];
      const stats = calculateAttendanceStats(userStart, workingDays, cancelledDays, userLogs);
      return { user: u, stats };
    });
  }, [users, logs, workingDays, cancelledDays]);

  const sortedStats = useMemo(() => {
    return [...statsList].sort((a, b) => {
      let valA: any, valB: any;
      if (sortKey === "name") { valA = a.user.full_name; valB = b.user.full_name; }
      if (sortKey === "present") { valA = a.stats.present; valB = b.stats.present; }
      if (sortKey === "absent") { valA = a.stats.absent; valB = b.stats.absent; }
      if (sortKey === "percentage") { valA = a.stats.percentage; valB = b.stats.percentage; }

      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [statsList, sortKey, sortAsc]);

  const kpis = useMemo(() => {
    if (statsList.length === 0) return { totalUsers: 0, workingDays: workingDays.length, avgPercentage: 0, topAttender: "-" };
    const sumPerc = statsList.reduce((acc, s) => acc + s.stats.percentage, 0);
    const top = [...statsList].sort((a, b) => b.stats.percentage - a.stats.percentage)[0];
    
    return {
      totalUsers: users.length,
      workingDays: workingDays.length,
      avgPercentage: sumPerc / users.length,
      topAttender: top ? top.user.full_name : "-"
    };
  }, [statsList, users.length, workingDays.length]);

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else { setSortKey(key); setSortAsc(false); }
  };

  if (loading) return <div className="card"><span className="spinner" /> Loading Statistics...</div>;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* KPI Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
        <div className="card" style={{ padding: 24 }}>
          <h4 className="text-muted mb-2">Total Members</h4>
          <h2 style={{ fontSize: 32, margin: 0 }}>{kpis.totalUsers}</h2>
        </div>
        <div className="card" style={{ padding: 24 }}>
          <h4 className="text-muted mb-2">Working Days</h4>
          <h2 style={{ fontSize: 32, margin: 0 }}>{kpis.workingDays}</h2>
        </div>
        <div className="card" style={{ padding: 24 }}>
          <h4 className="text-muted mb-2">Average Attendance</h4>
          <h2 style={{ fontSize: 32, margin: 0 }}>{kpis.avgPercentage.toFixed(1)}%</h2>
        </div>
        <div className="card" style={{ padding: 24 }}>
          <h4 className="text-muted mb-2">Top Attender</h4>
          <h2 style={{ fontSize: 20, margin: 0, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {kpis.topAttender}
          </h2>
        </div>
      </div>

      {/* Leaderboard Table */}
      <div className="card">
        <div className="card-header">
          <h3>Leaderboard</h3>
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th onClick={() => toggleSort("name")} style={{ cursor: "pointer" }}>
                  Name {sortKey === "name" && (sortAsc ? "↑" : "↓")}
                </th>
                <th>Identifier</th>
                <th onClick={() => toggleSort("present")} style={{ cursor: "pointer", textAlign: "center" }}>
                  Present {sortKey === "present" && (sortAsc ? "↑" : "↓")}
                </th>
                <th onClick={() => toggleSort("absent")} style={{ cursor: "pointer", textAlign: "center" }}>
                  Absent {sortKey === "absent" && (sortAsc ? "↑" : "↓")}
                </th>
                <th onClick={() => toggleSort("percentage")} style={{ cursor: "pointer", textAlign: "right" }}>
                  Attendance % {sortKey === "percentage" && (sortAsc ? "↑" : "↓")}
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedStats.map(({ user, stats }) => (
                <tr key={user.id}>
                  <td style={{ fontWeight: 500 }}>{user.full_name}</td>
                  <td><code style={{ fontSize: "var(--text-xs)" }}>{user.identifier}</code></td>
                  <td style={{ textAlign: "center", color: "var(--color-success)", fontWeight: 600 }}>{stats.present}</td>
                  <td style={{ textAlign: "center", color: "var(--color-danger)", fontWeight: 600 }}>{stats.absent}</td>
                  <td style={{ textAlign: "right", fontWeight: "bold" }}>{stats.percentage.toFixed(1)}%</td>
                </tr>
              ))}
              {sortedStats.length === 0 && (
                <tr><td colSpan={5} style={{ textAlign: "center", padding: 32 }}>No data available</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
