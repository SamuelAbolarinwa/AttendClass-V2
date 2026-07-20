import { useState, useRef, type FormEvent, type ChangeEvent } from "react";
import { supabase } from "../lib/supabase";
import { useAuth } from "../contexts/AuthContext";

interface Props {
  onClose: (didAdd: boolean) => void;
}

interface StudentEntry {
  name: string;
  matric: string;
}

interface ResultCreated {
  name: string;
  identifier: string;
  default_password: string;
}

interface ResultSkipped {
  name: string;
  identifier: string;
  reason: string;
}

interface SubmitResult {
  created: ResultCreated[];
  skipped: ResultSkipped[];
}

type Tab = "manual" | "bulk";

export function AddStudentModal({ onClose }: Props) {
  const { account } = useAuth();
  const [tab, setTab] = useState<Tab>("manual");

  const [manualName, setManualName] = useState("");
  const [manualMatric, setManualMatric] = useState("");

  const [bulkText, setBulkText] = useState("");
  const [parsedRows, setParsedRows] = useState<StudentEntry[]>([]);
  const [showPreview, setShowPreview] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<SubmitResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // ── CSV Parsing ──────────────────────────────────────────────────────────
  function parseCSVText(text: string): StudentEntry[] {
    const lines = text.trim().split(/\r?\n/).filter((l) => l.trim());
    const entries: StudentEntry[] = [];
    for (const line of lines) {
      if (/^\s*name\s*[,\t]/i.test(line)) continue;
      const parts = line.split(/[,\t]/).map((p) => p.trim().replace(/^"|"$/g, ""));
      if (parts.length >= 2 && parts[0] && parts[1]) {
        entries.push({ name: parts[0], matric: parts[1] });
      }
    }
    return entries;
  }

  function handleBulkTextPreview() {
    setParsedRows(parseCSVText(bulkText));
    setShowPreview(true);
  }

  function handleFileUpload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      setBulkText(text);
      setParsedRows(parseCSVText(text));
      setShowPreview(true);
    };
    reader.readAsText(file);
  }

  // ── Submission via platform_admin RPC ────────────────────────────────────
  async function submitStudents(students: StudentEntry[]) {
    setSubmitting(true);
    setError(null);
    setResult(null);

    if (!account?.token) {
      setError("Not authenticated. Please log in again.");
      setSubmitting(false);
      return;
    }

    const users = students.map((s) => ({
      name: s.name,
      identifier: s.matric,
      role: "user",
    }));

    const { data, error: rpcErr } = await supabase.rpc("platform_admin", {
      p_token: account.token,
      p_op: "addUsers",
      p_args: { users },
    });

    if (rpcErr) {
      setError(rpcErr.message);
    } else {
      const res = data as Record<string, unknown>;
      if (!res.ok) {
        setError((res.error as string) || "Operation failed");
      } else {
        setResult({
          created: (res.created as ResultCreated[]) || [],
          skipped: (res.skipped as ResultSkipped[]) || [],
        });
      }
    }
    setSubmitting(false);
  }

  function handleManualSubmit(e: FormEvent) {
    e.preventDefault();
    if (!manualName.trim() || !manualMatric.trim()) return;
    submitStudents([{ name: manualName.trim(), matric: manualMatric.trim() }]);
  }

  function handleBulkSubmit() {
    if (parsedRows.length === 0) return;
    submitStudents(parsedRows);
  }

  const didAdd = result ? result.created.length > 0 : false;

  return (
    <div className="modal-overlay" onClick={() => onClose(didAdd)}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Add Members</h2>
          <button className="modal-close" onClick={() => onClose(didAdd)}>×</button>
        </div>

        <div className="modal-body">
          {result ? (
            <div className="results-panel">
              <div className="results-summary">
                <div className="results-stat" style={{ background: "var(--color-success-bg)", color: "var(--color-success)", padding: "8px 16px", borderRadius: 8 }}>
                  ✓ {result.created.length} created
                </div>
                {result.skipped.length > 0 && (
                  <div className="results-stat" style={{ background: "var(--color-warning-bg)", color: "var(--color-warning)", padding: "8px 16px", borderRadius: 8 }}>
                    ⚠ {result.skipped.length} skipped
                  </div>
                )}
              </div>

              {result.created.length > 0 && (
                <div className="mb-4">
                  <h4 style={{ fontSize: "var(--text-sm)", fontWeight: 600, marginBottom: 8 }}>Created</h4>
                  <div className="table-wrapper card" style={{ border: "1px solid var(--color-border)" }}>
                    <table>
                      <thead><tr><th>Name</th><th>Identifier</th><th>Default Password</th></tr></thead>
                      <tbody>
                        {result.created.map((s, i) => (
                          <tr key={i}>
                            <td>{s.name}</td>
                            <td><code style={{ fontSize: "var(--text-xs)" }}>{s.identifier}</code></td>
                            <td><code style={{ fontSize: "var(--text-xs)" }}>{s.default_password}</code></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {result.skipped.length > 0 && (
                <div>
                  <h4 style={{ fontSize: "var(--text-sm)", fontWeight: 600, marginBottom: 8 }}>Skipped</h4>
                  <div className="table-wrapper card" style={{ border: "1px solid var(--color-border)" }}>
                    <table>
                      <thead><tr><th>Name</th><th>Identifier</th><th>Reason</th></tr></thead>
                      <tbody>
                        {result.skipped.map((s, i) => (
                          <tr key={i}>
                            <td>{s.name}</td>
                            <td><code style={{ fontSize: "var(--text-xs)" }}>{s.identifier}</code></td>
                            <td className="text-sm" style={{ color: "var(--color-warning)" }}>{s.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <>
              <div className="tabs">
                <button className={`tab ${tab === "manual" ? "active" : ""}`}
                  onClick={() => { setTab("manual"); setShowPreview(false); setError(null); }}>Manual</button>
                <button className={`tab ${tab === "bulk" ? "active" : ""}`}
                  onClick={() => { setTab("bulk"); setError(null); }}>Bulk Import</button>
              </div>

              {error && <div className="alert alert-error">{error}</div>}

              {tab === "manual" && (
                <form onSubmit={handleManualSubmit}>
                  <div className="form-group">
                    <label htmlFor="manual-name">Full Name</label>
                    <input id="manual-name" type="text" className="form-input"
                      placeholder="e.g. Abolarinwa Samuel Ayomide"
                      value={manualName} onChange={(e) => setManualName(e.target.value)} required autoFocus />
                  </div>
                  <div className="form-group">
                    <label htmlFor="manual-matric">Matric Number</label>
                    <input id="manual-matric" type="text" className="form-input"
                      placeholder="e.g. 2022/1/86871ET"
                      value={manualMatric} onChange={(e) => setManualMatric(e.target.value)} required />
                  </div>
                  <button type="submit" className="btn btn-primary btn-block" disabled={submitting}>
                    {submitting ? <><span className="spinner" /> Adding…</> : "Add Member"}
                  </button>
                </form>
              )}

              {tab === "bulk" && !showPreview && (
                <div>
                  <div className="form-group">
                    <label htmlFor="bulk-textarea">Paste CSV or tab-separated rows (Name, Matric Number per line)</label>
                    <textarea id="bulk-textarea" className="form-input"
                      placeholder={"Adegboye Michael Adeoluwa, 2022/1/86885ET\nAbolarinwa Samuel Ayomide, 2022/1/86871ET"}
                      value={bulkText} onChange={(e) => setBulkText(e.target.value)} rows={8} />
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "var(--space-4)", marginBottom: "var(--space-4)" }}>
                    <button type="button" className="btn btn-primary" disabled={!bulkText.trim()} onClick={handleBulkTextPreview}>Preview</button>
                    <span className="text-muted text-sm">or</span>
                    <div className="dropzone" onClick={() => fileInputRef.current?.click()} style={{ flex: 1, padding: "var(--space-4)" }}>
                      <input ref={fileInputRef} type="file" accept=".csv,.txt" onChange={handleFileUpload} />
                      📄 Upload .csv file
                    </div>
                  </div>
                </div>
              )}

              {tab === "bulk" && showPreview && (
                <div>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "var(--space-4)" }}>
                    <p className="text-sm"><strong>{parsedRows.length}</strong> row{parsedRows.length !== 1 ? "s" : ""} parsed</p>
                    <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowPreview(false)}>← Edit</button>
                  </div>
                  <div className="table-wrapper card mb-4" style={{ maxHeight: 300, overflowY: "auto", border: "1px solid var(--color-border)" }}>
                    <table>
                      <thead><tr><th>#</th><th>Name</th><th>Matric Number</th></tr></thead>
                      <tbody>
                        {parsedRows.map((r, i) => (
                          <tr key={i}>
                            <td className="text-muted">{i + 1}</td>
                            <td>{r.name}</td>
                            <td><code style={{ fontSize: "var(--text-xs)" }}>{r.matric}</code></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <button type="button" className="btn btn-primary btn-block"
                    disabled={submitting || parsedRows.length === 0} onClick={handleBulkSubmit}>
                    {submitting
                      ? <><span className="spinner" /> Importing {parsedRows.length} members…</>
                      : `Import ${parsedRows.length} Member${parsedRows.length !== 1 ? "s" : ""}`}
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {result && (
          <div className="modal-footer">
            <button className="btn btn-secondary" onClick={() => onClose(didAdd)}>Close</button>
          </div>
        )}
      </div>
    </div>
  );
}
