import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { DashboardLayout } from "./layouts/DashboardLayout";
import { Login } from "./pages/Login";
import { ResetPassword } from "./pages/ResetPassword";
import { Students } from "./pages/administrator/Students";

import { EnrollFacePage } from "./pages/EnrollFace";

import { Register } from "./pages/administrator/Register";
import { Statistics } from "./pages/administrator/Statistics";
import { CancelledDays } from "./pages/administrator/CancelledDays";
import { Settings } from "./pages/administrator/Settings";
import { UserDashboard } from "./pages/UserDashboard";

export function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/enroll-face" element={<EnrollFacePage />} />

          {/* Administrator routes */}
          <Route
            element={
              <ProtectedRoute allowedRoles={["administrator"]}>
                <DashboardLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/administrator/students" element={<Students />} />
            <Route path="/administrator/register" element={<Register />} />
            <Route path="/administrator/statistics" element={<Statistics />} />
            <Route path="/administrator/cancelled-days" element={<CancelledDays />} />
            <Route path="/administrator/settings" element={<Settings />} />
          </Route>

          {/* User routes */}
          <Route
            element={
              <ProtectedRoute allowedRoles={["user"]}>
                <DashboardLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard" element={<UserDashboard />} />
          </Route>

          {/* Default redirect */}
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
