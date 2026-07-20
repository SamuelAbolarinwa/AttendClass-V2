import { useEffect, useState } from "react";
import { supabase } from "../../lib/supabase";
import { AddStudentModal } from "../../components/AddStudentModal";

interface Student {
  id: string;
  full_name: string;
  matric_number: string | null;
  must_change_password: boolean;
  created_at: string;
}

export function Students() {
  const [students, setStudents] = useState<Student[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);

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
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {modalOpen && <AddStudentModal onClose={handleModalClose} />}
    </>
  );
}
