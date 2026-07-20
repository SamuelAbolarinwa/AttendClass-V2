import { FaceEnrollment } from "../components/FaceEnrollment";
import { useAuth } from "../contexts/AuthContext";
import { Navigate } from "react-router-dom";

export function EnrollFacePage() {
  const { account, loading } = useAuth();

  if (loading) {
    return (
      <div className="login-page">
        <div className="spinner" style={{ width: 32, height: 32 }} />
      </div>
    );
  }
  
  if (!account) return <Navigate to="/login" replace />;

  return (
    <div className="login-page">
      <div className="login-card" style={{ maxWidth: 640 }}>
        <FaceEnrollment />
      </div>
    </div>
  );
}
