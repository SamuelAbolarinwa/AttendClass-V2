import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

interface Props {
  children: React.ReactNode;
  allowedRoles?: string[];
}

export function ProtectedRoute({ children, allowedRoles }: Props) {
  const { account, loading } = useAuth();

  if (loading) {
    return (
      <div className="login-page">
        <div className="spinner" style={{ width: 32, height: 32 }} />
      </div>
    );
  }

  if (!account) {
    return <Navigate to="/login" replace />;
  }

  if (account.must_change_password) {
    return <Navigate to="/reset-password" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(account.role)) {
    return (
      <div className="login-page">
        <div className="login-card text-center">
          <h1>Access Denied</h1>
          <p className="subtitle">You don't have permission to view this page.</p>
          <button className="btn btn-secondary" onClick={() => window.history.back()}>
            Go Back
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
