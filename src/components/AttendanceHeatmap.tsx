import React, { useState } from "react";
import { isCountableDay } from "../utils/attendanceHelpers";

interface Log {
  verified_at: string;
}

interface AttendanceHeatmapProps {
  logs: Log[];
  trackingStartDate: string;
  endDate: Date;
  cancelledDays: Set<string>;
}

export function AttendanceHeatmap({ logs, trackingStartDate, endDate, cancelledDays }: AttendanceHeatmapProps) {
  const [activeTooltip, setActiveTooltip] = useState<{ date: string; status: string } | null>(null);

  const startObj = new Date(trackingStartDate);
  startObj.setDate(1);

  // We want to generate months from the tracking start date month up to the end date month
  const months: Date[] = [];
  const currentMonth = new Date(startObj);
  while (
    currentMonth.getFullYear() < endDate.getFullYear() ||
    (currentMonth.getFullYear() === endDate.getFullYear() && currentMonth.getMonth() <= endDate.getMonth())
  ) {
    months.push(new Date(currentMonth));
    currentMonth.setMonth(currentMonth.getMonth() + 1);
  }

  const todayStr = new Date().toISOString().split("T")[0];

  return (
    <div className="card" style={{ marginBottom: "var(--space-8)" }}>
      <div className="card-header">
        <h3>Attendance History</h3>
      </div>
      <div className="card-body">
        <div style={{ display: "flex", overflowX: "auto", gap: "var(--space-6)", paddingBottom: "var(--space-4)" }}>
          {months.map((monthDate, idx) => {
            const year = monthDate.getFullYear();
            const month = monthDate.getMonth();

            const daysInMonth = new Date(year, month + 1, 0).getDate();
            const firstDayOfWeek = new Date(year, month, 1).getDay();

            const days: (string | null)[] = Array(firstDayOfWeek).fill(null);
            for (let i = 1; i <= daysInMonth; i++) {
              const dateStr = [
                year,
                String(month + 1).padStart(2, "0"),
                String(i).padStart(2, "0"),
              ].join("-");
              days.push(dateStr);
            }

            return (
              <div key={idx} style={{ flexShrink: 0 }}>
                <div style={{ fontSize: "var(--text-sm)", fontWeight: 600, marginBottom: "var(--space-2)", textAlign: "center" }}>
                  {monthDate.toLocaleString("default", { month: "short", year: "numeric" })}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 16px)", gap: "4px" }}>
                  {["S", "M", "T", "W", "T", "F", "S"].map((d, i) => (
                    <div key={i} style={{ fontSize: "10px", textAlign: "center", color: "var(--color-text-muted)" }}>
                      {d}
                    </div>
                  ))}
                  {days.map((dateStr, i) => {
                    if (!dateStr) return <div key={i} />;

                    const isPreStart = dateStr < trackingStartDate;
                    const isCancelled = cancelledDays.has(dateStr);
                    const isPresent = logs.some((l) => l.verified_at.startsWith(dateStr));
                    const dObj = new Date(dateStr);
                    const isWeekend = dObj.getDay() === 0 || dObj.getDay() === 6;
                    const isFuture = dateStr > todayStr;

                    let color = "var(--color-bg)";
                    let status = "Not yet tracked";

                    if (isPreStart) {
                      color = "var(--color-border)";
                      status = "Not yet tracked";
                    } else if (isCancelled) {
                      color = "var(--color-text-muted)";
                      status = "Holiday";
                    } else if (isWeekend) {
                      color = "var(--color-border)";
                      status = "Weekend";
                    } else if (isPresent) {
                      color = "var(--color-success)";
                      status = "Present";
                    } else if (!isFuture) {
                      color = "var(--color-error)";
                      status = "Absent";
                    } else {
                      color = "var(--color-bg)";
                      status = "Future";
                    }

                    return (
                      <div
                        key={dateStr}
                        style={{
                          width: 16,
                          height: 16,
                          backgroundColor: color,
                          borderRadius: 2,
                          cursor: "pointer",
                          border: status === "Future" ? "1px dashed var(--color-border)" : "none"
                        }}
                        onClick={() => setActiveTooltip({ date: dateStr, status })}
                        onMouseEnter={() => setActiveTooltip({ date: dateStr, status })}
                        onMouseLeave={() => setActiveTooltip(null)}
                      />
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        {/* Legend & Tooltip Area */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "var(--space-4)", flexWrap: "wrap", gap: "var(--space-4)" }}>
          <div style={{ display: "flex", gap: "var(--space-4)", fontSize: "var(--text-xs)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
              <div style={{ width: 12, height: 12, backgroundColor: "var(--color-success)", borderRadius: 2 }} /> Present
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
              <div style={{ width: 12, height: 12, backgroundColor: "var(--color-error)", borderRadius: 2 }} /> Absent
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
              <div style={{ width: 12, height: 12, backgroundColor: "var(--color-text-muted)", borderRadius: 2 }} /> Holiday
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
              <div style={{ width: 12, height: 12, backgroundColor: "var(--color-border)", borderRadius: 2 }} /> Not tracked
            </div>
          </div>
          
          <div style={{ minHeight: "20px", fontSize: "var(--text-sm)", fontWeight: 500, color: "var(--color-text)" }}>
            {activeTooltip ? `${activeTooltip.date}: ${activeTooltip.status}` : "Hover or tap a cell for details"}
          </div>
        </div>
      </div>
    </div>
  );
}
