import { useState } from "react";
import { supabase } from "../lib/supabase";
import { useAuth } from "../contexts/AuthContext";
import { useFaceDetection } from "../hooks/useFaceDetection";

export function FaceEnrollment() {
  const { account } = useAuth();
  const [submitting, setSubmitting] = useState(false);
  
  const {
    videoRef,
    modelsLoaded,
    detecting,
    setDetecting,
    descriptor,
    status,
    setStatus,
    error,
    setError,
    stopStream
  } = useFaceDetection();

  // Handle capture & submission
  const handleCapture = async () => {
    if (!descriptor || !account) return;
    
    setSubmitting(true);
    setError(null);
    setDetecting(false); // Pause detection
    setStatus("Saving face data...");

    // Convert Float32Array to standard array for JSON transport
    const embeddingArray = Array.from(descriptor);
    // pgvector expects a string representation of the array e.g. "[1.2, 3.4, ...]"
    const embeddingStr = `[${embeddingArray.join(',')}]`;

    const { data, error: rpcErr } = await supabase.rpc("platform_enroll_face", {
      p_token: account.token,
      p_embedding: embeddingStr as any // Supabase TS types don't know about vector
    });

    if (rpcErr) {
      setError(rpcErr.message);
      setDetecting(true); // Resume
      setSubmitting(false);
      return;
    }

    const res = data as Record<string, unknown>;
    if (!res.ok) {
      setError((res.error as string) || "Failed to save face enrollment.");
      setDetecting(true);
      setSubmitting(false);
      return;
    }

    setStatus("Success! Redirecting...");
    
    stopStream();

    // Redirect to home
    setTimeout(() => {
      const home = account.role === "administrator" ? "/administrator/students" :
                   account.role === "manager" ? "/manager/dashboard" :
                   "/dashboard";
      window.location.href = home;
    }, 1000);
  };

  return (
    <div className="face-enrollment-container" style={{ maxWidth: 640, margin: "0 auto", textAlign: "center" }}>
      <h2>Face Enrollment</h2>
      
      {error && <div className="alert alert-error" style={{ marginBottom: 16 }}>{error}</div>}
      
      <p className="text-muted mb-4">{status}</p>

      <div style={{ position: "relative", width: "100%", maxWidth: 480, margin: "0 auto", overflow: "hidden", borderRadius: 16, backgroundColor: "#000" }}>
        <video 
          ref={videoRef} 
          autoPlay 
          playsInline 
          muted 
          style={{ width: "100%", height: "auto", display: "block", transform: "scaleX(-1)" }} // mirror
        />
        
        {/* Overlay Guide */}
        <div style={{
          position: "absolute",
          top: "15%", left: "25%", right: "25%", bottom: "15%",
          border: `4px solid ${descriptor ? "var(--color-success)" : "rgba(255,255,255,0.4)"}`,
          borderRadius: "50%",
          boxShadow: "0 0 0 9999px rgba(0,0,0,0.5)",
          pointerEvents: "none",
          transition: "border-color 0.3s ease"
        }} />
      </div>

      <div style={{ marginTop: 24 }}>
        <button 
          className="btn btn-primary btn-lg" 
          disabled={!descriptor || submitting}
          onClick={handleCapture}
        >
          {submitting ? <><span className="spinner" /> Saving...</> : "Capture & Complete"}
        </button>
      </div>
      
      {!modelsLoaded && !error && (
        <div style={{ marginTop: 20 }}>
          <span className="spinner" /> Loading AI models (~7MB)
        </div>
      )}
    </div>
  );
}
