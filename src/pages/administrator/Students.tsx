import { useEffect, useState } from "react";
import { supabase } from "../../lib/supabase";
import { useAuth } from "../../contexts/AuthContext";
import { AddStudentModal } from "../../components/AddStudentModal";

interface Student {
  id: string;
  full_name: string;
  matric_number: string | null;
  must_change_password: boolean;
  created_at: string;
}

export function Students() {
  const { account } = useAuth();
  const [students, setStudents] = useState<Student[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [resetResult, setResetResult] = useState<{name: string, password: string} | null>(null);
  const [studentToReset, setStudentToReset] = useState<Student | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchStudents = async () => {
    setLoading(true);
    const { data, error } = await supabase
      .from("profiles")
      .select("id, full_name, matric_number, must_change_password, created_at")
      .eq("role", "user")
      .order("full_name");

    if (error) {
      console.error("Failed to fetch members:", error.message);
    } else {
      setStudents(data ?? []);
    }
    setLoading(false);
  };

  useEffect(() => { fetchStudents(); }, []);

  const handleModalClose = (didAdd: boolean) => {
    setModalOpen(false);
    if (didAdd) fetchStudents();
  };

  const handleResetPassword = (student: Student) => {
    setStudentToReset(student);
  };

  const executeResetPassword = async (student: Student) => {
    if (!account) return;

    try {
      const { data, error } = await supabase.rpc("platform_admin", {
        p_token: account.token,
        p_op: "resetPassword",
        p_args: { account_id: student.id }
      });

      if (error) throw error;
      
      const res = data as any;
      if (!res.ok) throw new Error(res.error || "Failed to reset password");

      setResetResult({ name: student.full_name, password: res.new_default_password });
      fetchStudents();
    } catch (err: any) {
      setErrorMessage(`Error resetting password: ${err.message}`);
    }
  };

  return (
    <>
      <div className="card">
        <div className="card-header">
          <div>
            <h3>Members</h3>
            <p className="text-sm text-muted" style={{ marginTop: 2 }}>
              {students.length} member{students.length !== 1 ? "s" : ""} registered
            </p>
          </div>
          <button id="add-member-btn" className="btn btn-primary" onClick={() => setModalOpen(true)}>
            + Add Member
          </button>
        </div>

        <div className="table-wrapper">
          {loading ? (
            <div className="table-empty"><span className="spinner" /></div>
          ) : students.length === 0 ? (
            <div className="table-empty">
              <p>No members yet.</p>
              <p className="mt-2">Click "Add Member" to get started.</p>
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Matric Number</th>
                  <th>Status</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {students.map((s) => (
                  <tr key={s.id}>
                    <td style={{ fontWeight: 500 }}>{s.full_name}</td>
                    <td>
                      <code style={{ fontSize: "var(--text-xs)", background: "var(--color-bg)", padding: "2px 6px", borderRadius: 4 }}>
                        {s.matric_number ?? "—"}
                      </code>
                    </td>
                    <td>
                      {s.must_change_password ? (
                        <span className="badge badge-warning">Pending Setup</span>
                      ) : (
                        <span className="badge badge-success">Active</span>
                      )}
                    </td>
                    <td className="text-muted text-sm">
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                    <td>
                      <button 
                        className="btn btn-secondary btn-sm"
                        onClick={() => handleResetPassword(s)}
                      >
                        Reset Password
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {modalOpen && <AddStudentModal onClose={handleModalClose} />}

      {studentToReset && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 400 }}>
            <div className="modal-header">
              <h2>Confirm Reset</h2>
              <button className="modal-close" onClick={() => setStudentToReset(null)}>×</button>
            </div>
            <div className="modal-body">
              <p>Are you sure you want to reset the password for <strong>{studentToReset.full_name}</strong>?</p>
              <p className="text-sm text-muted mt-2">They will be forced to change it on their next login.</p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setStudentToReset(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={() => {
                const s = studentToReset;
                setStudentToReset(null);
                executeResetPassword(s);
              }}>Reset Password</button>
            </div>
          </div>
        </div>
      )}

      {errorMessage && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 400 }}>
            <div className="modal-header">
              <h2>Error</h2>
              <button className="modal-close" onClick={() => setErrorMessage(null)}>×</button>
            </div>
            <div className="modal-body">
              <p>{errorMessage}</p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={() => setErrorMessage(null)}>OK</button>
            </div>
          </div>
        </div>
      )}

      {resetResult && (
        <div className="modal-overlay">
          <div className="modal" style={{ maxWidth: 400 }}>
            <div className="modal-header">
              <h2>Password Reset Successful</h2>
              <button className="modal-close" onClick={() => setResetResult(null)}>×</button>
            </div>
            <div className="modal-body">
              <p>The password for <strong>{resetResult.name}</strong> has been reset to the default.</p>
              <div style={{ margin: "var(--space-4) 0", padding: "var(--space-3)", background: "var(--color-bg)", borderRadius: "var(--radius-md)", border: "1px solid var(--color-border)", textAlign: "center" }}>
                <code style={{ fontSize: "var(--text-lg)", fontWeight: 700 }}>{resetResult.password}</code>
              </div>
              <p className="text-sm text-muted">
                Please securely relay this to the user. They will be forced to change this password on their next login.
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={() => setResetResult(null)}>Done</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
