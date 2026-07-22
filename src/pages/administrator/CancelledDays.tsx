import { useEffect, useState } from "react";
import { supabase } from "../../lib/supabase";
import { useAuth } from "../../contexts/AuthContext";

interface CancelledDay {
  id: string;
  cancelled_date: string;
  reason: string | null;
}

export function CancelledDays() {
  const { account } = useAuth();
  const [days, setDays] = useState<CancelledDay[]>([]);
  const [loading, setLoading] = useState(true);
  const [dayToRestore, setDayToRestore] = useState<string | null>(null);

  // Form State
  const [mode, setMode] = useState<"single" | "range" | "multiple">("single");
  const [reason, setReason] = useState("Public Holiday");
  
  const [singleDate, setSingleDate] = useState("");
  
  const [rangeStart, setRangeStart] = useState("");
  const [rangeEnd, setRangeEnd] = useState("");
  const [skipWeekends, setSkipWeekends] = useState(true);
  
  const [multipleDates, setMultipleDates] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDays();
  }, []);

  const fetchDays = async () => {
    setLoading(true);
    const { data } = await supabase.from("cancelled_days").select("*").order("cancelled_date", { ascending: false });
    if (data) setDays(data);
    setLoading(false);
  };

  const handleRestore = (id: string) => {
    setDayToRestore(id);
  };

  const executeRestore = async (id: string) => {
    if (!account) return;
    
    await supabase.rpc("platform_delete_cancelled_day", { p_token: account.token, p_id: id });
    fetchDays();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!account) return;
    setError(null);
    setSubmitting(true);

    let datesToUpsert: string[] = [];

    if (mode === "single") {
      if (!singleDate) { setError("Select a date"); setSubmitting(false); return; }
      datesToUpsert.push(singleDate);
    } 
    else if (mode === "range") {
      if (!rangeStart || !rangeEnd || rangeStart > rangeEnd) {
        setError("Invalid date range"); setSubmitting(false); return;
      }
      
      const start = new Date(rangeStart);
      const end = new Date(rangeEnd);
      start.setUTCHours(0, 0, 0, 0);
      end.setUTCHours(0, 0, 0, 0);

      const curr = new Date(start);
      while (curr <= end) {
        const dayOfWeek = curr.getUTCDay();
        if (!skipWeekends || (dayOfWeek !== 0 && dayOfWeek !== 6)) {
          datesToUpsert.push(curr.toISOString().split("T")[0]);
        }
        curr.setUTCDate(curr.getUTCDate() + 1);
      }
    } 
    else if (mode === "multiple") {
      const parts = multipleDates.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
      for (const p of parts) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(p)) {
          setError(`Invalid date format: ${p}. Use YYYY-MM-DD.`);
          setSubmitting(false); return;
        }
        datesToUpsert.push(p);
      }
      if (datesToUpsert.length === 0) {
        setError("Enter at least one valid date"); setSubmitting(false); return;
      }
    }

    if (datesToUpsert.length === 0) {
      setError("No valid days selected to cancel.");
      setSubmitting(false); return;
    }

    const { error: rpcErr } = await supabase.rpc("platform_upsert_cancelled_day", {
      p_token: account.token,
      p_dates: datesToUpsert,
      p_reason: reason.trim() || null
    });

    if (rpcErr) {
      setError(rpcErr.message);
    } else {
      // Reset forms
      setSingleDate("");
      setRangeStart(""); setRangeEnd("");
      setMultipleDates("");
      setReason("Public Holiday");
      fetchDays();
    }
    setSubmitting(false);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 24, alignItems: "start" }}>
      {/* Form Sidebar */}
      <div className="card">
        <div className="card-header">
          <h3>Cancel Days</h3>
        </div>
        <div className="card-body">
          <div className="tabs mb-4">
            <button className={`tab ${mode === "single" ? "active" : ""}`} onClick={() => { setMode("single"); setError(null); }}>Single</button>
            <button className={`tab ${mode === "range" ? "active" : ""}`} onClick={() => { setMode("range"); setError(null); }}>Range</button>
            <button className={`tab ${mode === "multiple" ? "active" : ""}`} onClick={() => { setMode("multiple"); setError(null); }}>Multiple</button>
          </div>

          {error && <div className="alert alert-error mb-4">{error}</div>}

          <form onSubmit={handleSubmit}>
            {mode === "single" && (
              <div className="form-group">
                <label>Date</label>
                <input type="date" className="form-input" value={singleDate} onChange={e => setSingleDate(e.target.value)} required />
              </div>
            )}

            {mode === "range" && (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                  <div className="form-group">
                    <label>Start Date</label>
                    <input type="date" className="form-input" value={rangeStart} onChange={e => setRangeStart(e.target.value)} required />
                  </div>
                  <div className="form-group">
                    <label>End Date</label>
                    <input type="date" className="form-input" value={rangeEnd} onChange={e => setRangeEnd(e.target.value)} required />
                  </div>
                </div>
                <div className="form-group" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <input type="checkbox" id="skip-weekends" checked={skipWeekends} onChange={e => setSkipWeekends(e.target.checked)} />
                  <label htmlFor="skip-weekends" style={{ margin: 0 }}>Skip Weekends (Sat/Sun)</label>
                </div>
              </>
            )}

            {mode === "multiple" && (
              <div className="form-group">
                <label>Dates (YYYY-MM-DD, comma separated)</label>
                <textarea className="form-input" rows={4} value={multipleDates} onChange={e => setMultipleDates(e.target.value)} placeholder="2026-12-25, 2026-12-26" required />
              </div>
            )}

            <div className="form-group">
              <label>Reason (Optional)</label>
              <input type="text" className="form-input" value={reason} onChange={e => setReason(e.target.value)} placeholder="e.g. Public Holiday" />
            </div>

            <button type="submit" className="btn btn-primary btn-block" disabled={submitting}>
              {submitting ? <><span className="spinner" /> Saving...</> : "Mark as Cancelled"}
            </button>
          </form>
        </div>
      </div>

      {/* Existing Cancelled Days Table */}
      <div className="card">
        <div className="card-header">
          <h3>Cancelled Days Registry</h3>
        </div>
        <div className="table-wrapper">
          {loading ? (
            <div className="table-empty"><span className="spinner" /></div>
          ) : days.length === 0 ? (
            <div className="table-empty">No cancelled days recorded.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Reason</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {days.map(d => (
                  <tr key={d.id}>
                    <td style={{ fontWeight: 500 }}>{d.cancelled_date}</td>
                    <td className="text-muted">{d.reason || "—"}</td>
                    <td style={{ textAlign: "right" }}>
                      <button className="btn btn-ghost btn-sm" style={{ color: "var(--color-danger)" }} onClick={() => handleRestore(d.id)}>
                        Restore
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {dayToRestore && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 400 }}>
            <div className="modal-header">
              <h2>Confirm Restore</h2>
              <button className="modal-close" onClick={() => setDayToRestore(null)}>×</button>
            </div>
            <div className="modal-body">
              <p>Are you sure you want to restore this day? It will now count towards attendance.</p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setDayToRestore(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={() => {
                const id = dayToRestore;
                setDayToRestore(null);
                executeRestore(id);
              }}>Restore Day</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
