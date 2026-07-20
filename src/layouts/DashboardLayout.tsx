import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export function DashboardLayout() {
  const { account, signOut } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const initials = account?.full_name
    ?.split(" ")
    .map((w) => w[0])
    .slice(0, 2)
    .join("")
    .toUpperCase() ?? "?";

  const roleLabel = account?.role === "administrator" ? "Administrator"
    : account?.role === "manager" ? "Manager"
    : account?.role === "user" ? "Member"
    : account?.role ?? "";

  return (
    <div className="dashboard">
      <div
        className={`sidebar-overlay ${sidebarOpen ? "open" : ""}`}
        onClick={() => setSidebarOpen(false)}
      />

      <aside className={`sidebar ${sidebarOpen ? "open" : ""}`}>
        <div className="sidebar-brand">
          <h1>AttendClass</h1>
          <span>v2 Dashboard</span>
        </div>

        <nav className="sidebar-nav">
          {account?.role === "administrator" && (
            <>
              <NavLink
                to="/administrator/register"
                onClick={() => setSidebarOpen(false)}
                className={({ isActive }) => isActive ? "active" : ""}
              >
                📅 Register Matrix
              </NavLink>
              <NavLink
                to="/administrator/statistics"
                onClick={() => setSidebarOpen(false)}
                className={({ isActive }) => isActive ? "active" : ""}
              >
                📊 Statistics
              </NavLink>
              <NavLink
                to="/administrator/students"
                onClick={() => setSidebarOpen(false)}
                className={({ isActive }) => isActive ? "active" : ""}
              >
                👥 Members
              </NavLink>
              <NavLink
                to="/administrator/cancelled-days"
                onClick={() => setSidebarOpen(false)}
                className={({ isActive }) => isActive ? "active" : ""}
              >
                🛑 Cancelled Days
              </NavLink>
              <NavLink
                to="/administrator/settings"
                onClick={() => setSidebarOpen(false)}
                className={({ isActive }) => isActive ? "active" : ""}
              >
                ⚙️ Settings
              </NavLink>
            </>
          )}

          {account?.role === "manager" && (
            <NavLink
              to="/manager/dashboard"
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) => isActive ? "active" : ""}
            >
              📊 Dashboard
            </NavLink>
          )}

          {account?.role === "user" && (
            <NavLink
              to="/dashboard"
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) => isActive ? "active" : ""}
            >
              📋 My Attendance
            </NavLink>
          )}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="sidebar-user-avatar">{initials}</div>
            <div className="sidebar-user-info">
              <div className="sidebar-user-name">{account?.full_name}</div>
              <div className="sidebar-user-role">{roleLabel}</div>
            </div>
          </div>
          <NavLink
            to="/enroll-face"
            className="btn btn-ghost btn-sm btn-block mt-4"
            style={{ textDecoration: "none" }}
          >
            Re-enroll Face
          </NavLink>
          <button
            type="button"
            className="btn btn-ghost btn-sm btn-block mt-2"
            onClick={(e) => {
              e.preventDefault();
              signOut();
            }}
          >
            Sign Out
          </button>
        </div>
      </aside>

      <div className="main-content">
        <header className="topbar">
          <button
            className="mobile-menu-btn"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label="Toggle menu"
          >
            ☰
          </button>
          <div />
        </header>

        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
