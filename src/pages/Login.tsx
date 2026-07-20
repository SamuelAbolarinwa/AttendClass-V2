import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export function Login() {
  const { account, loading, signIn } = useAuth();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Redirect if already logged in
  if (!loading && account) {
    if (account.must_change_password) return <Navigate to="/reset-password" replace />;
    const home = account.role === "administrator" ? "/administrator/students" :
                 account.role === "manager" ? "/manager/dashboard" :
                 "/dashboard";
    return <Navigate to={home} replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    const { error: err } = await signIn(identifier.trim(), password);
    if (err) setError(err);
    setSubmitting(false);
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <h1>Welcome back</h1>
        <p className="subtitle">Sign in to AttendClass</p>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="login-identifier">Identifier</label>
            <input
              id="login-identifier"
              type="text"
              className="form-input"
              placeholder="Matric number or email"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              className="form-input"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-lg btn-block"
            disabled={submitting}
          >
            {submitting ? <><span className="spinner" /> Signing in…</> : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
