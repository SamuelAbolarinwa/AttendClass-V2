import { useState, useEffect } from "react";
import { supabase } from "../lib/supabase";
import { useAuth } from "../contexts/AuthContext";
import { useFaceDetection } from "../hooks/useFaceDetection";
import { BleCheckinFlow, BleCheckinResult } from "./BleCheckinFlow";

type FlowStep = "IDLE" | "VERIFY_FACE" | "CONNECT_BLE" | "SUCCESS" | "ALREADY_LOGGED" | "FAILED";

interface Props {
  onClose?: () => void;
  onSuccess?: () => void;
}

export function CheckInFlow({ onClose, onSuccess }: Props) {
  const { account } = useAuth();
  const [step, setStep] = useState<FlowStep>("VERIFY_FACE");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [loggedAt, setLoggedAt] = useState<string | null>(null);
  const [faceSimilarity, setFaceSimilarity] = useState<number | null>(null);

  return (
    <div className="checkin-flow-container">
      {/* Header/Stepper */}
      <div className="flex items-center gap-2 mb-4" style={{ justifyContent: "center" }}>
        <span className={`badge ${step === "VERIFY_FACE" ? "badge-primary" : "badge-neutral"}`}>1. Face</span>
        <span className="text-muted">→</span>
        <span className={`badge ${step === "CONNECT_BLE" ? "badge-primary" : "badge-neutral"}`}>2. BLE</span>
        <span className="text-muted">→</span>
        <span className={`badge ${["SUCCESS", "ALREADY_LOGGED"].includes(step) ? "badge-success" : step === "FAILED" ? "badge-error" : "badge-neutral"}`}>3. Result</span>
      </div>

      {step === "VERIFY_FACE" && (
        <FaceStep 
          onMatch={(similarity) => {
            setFaceSimilarity(similarity);
            setStep("CONNECT_BLE");
          }}
          onFail={(err) => {
            setErrorMsg(err);
            setStep("FAILED");
          }}
        />
      )}

      {step === "CONNECT_BLE" && (
        <BleCheckinFlow
          onSuccess={async (result) => {
            try {
              if (!account) throw new Error("Not logged in");
              if (faceSimilarity === null) throw new Error("Missing face similarity score");

              const { data, error } = await supabase.functions.invoke("verify-checkin", {
                body: {
                  session_token: account.token,
                  ble_short_code: result.deviceId,
                  ble_token: result.token,
                  rssi: result.rssi,
                  face_similarity: faceSimilarity
                }
              });

              if (error) {
                // If it's a 403 from the edge function (e.g. invalid_token), supabase-js might wrap it,
                // but let's check error message or data.error
                const serverErr = data?.error || error.message;
                if (serverErr === "invalid_token") {
                  throw new Error("Invalid BLE token. Please move closer to the class device and try again.");
                } else if (serverErr === "out_of_range") {
                  throw new Error("Move closer to the device and try again.");
                }
                throw new Error(serverErr || "Check-in verification failed");
              }

              if (!data?.ok) {
                throw new Error(data?.error || "Failed to log attendance");
              }

              if (data.already_logged_today) {
                setLoggedAt(new Date(data.logged_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                setStep("ALREADY_LOGGED");
              } else {
                setStep("SUCCESS");
                onSuccess?.();
              }
            } catch (err: any) {
              setErrorMsg(err.message);
              setStep("FAILED");
            }
          }}
          onFailure={(reason) => {
            setErrorMsg(reason);
            setStep("FAILED");
          }}
        />
      )}

      {step === "SUCCESS" && (
        <div className="card text-center" style={{ padding: "var(--space-8)" }}>
          <div style={{ fontSize: "3rem", marginBottom: "var(--space-4)", color: "var(--color-success)" }}>✅</div>
          <h3>Check-In Successful</h3>
          <p className="text-muted mb-4">Your attendance has been securely verified and logged.</p>
          <button className="btn btn-primary" onClick={onClose}>Done</button>
        </div>
      )}

      {step === "ALREADY_LOGGED" && (
        <div className="card text-center" style={{ padding: "var(--space-8)" }}>
          <div style={{ fontSize: "3rem", marginBottom: "var(--space-4)", color: "var(--color-success)" }}>📋</div>
          <h3>Already Checked In</h3>
          <p className="text-muted mb-4">You already checked in today at {loggedAt}.</p>
          <button className="btn btn-primary" onClick={onClose}>Done</button>
        </div>
      )}

      {step === "FAILED" && (
        <div className="card text-center" style={{ padding: "var(--space-8)", borderColor: "var(--color-error)" }}>
          <div style={{ fontSize: "3rem", marginBottom: "var(--space-4)", color: "var(--color-error)" }}>❌</div>
          <h3>Verification Failed</h3>
          <p className="text-muted mb-4">{errorMsg || "An unknown error occurred during check-in."}</p>
          <div className="flex gap-2" style={{ justifyContent: "center" }}>
            <button className="btn btn-primary" onClick={() => { setErrorMsg(null); setStep("VERIFY_FACE"); }}>Try Again</button>
            {onClose && <button className="btn btn-secondary" onClick={onClose}>Cancel</button>}
          </div>
        </div>
      )}
    </div>
  );
}

function FaceStep({ onMatch, onFail }: { onMatch: (similarity: number) => void, onFail: (err: string) => void }) {
  const { account } = useAuth();
  const [verifying, setVerifying] = useState(false);
  const {
    videoRef, modelsLoaded, detecting, setDetecting, descriptor, status, error, stopStream
  } = useFaceDetection();

  // Try matching whenever descriptor changes
  useEffect(() => {
    async function verifyFace() {
      if (!descriptor || !account || verifying) return;
      setVerifying(true);
      setDetecting(false); // Pause detection

      try {
        const embeddingArray = Array.from(descriptor);
        const embeddingStr = `[${embeddingArray.join(',')}]`;

        const { data, error: rpcErr } = await supabase.rpc("platform_verify_face", {
          p_token: account.token,
          p_embedding: embeddingStr as any
        });

        if (rpcErr) throw new Error(rpcErr.message);

        const res = data as any;
        if (!res.match) {
          throw new Error(res.error || `Face not recognized (Similarity: ${(res.similarity * 100).toFixed(1)}%)`);
        }

        // Match success
        stopStream();
        onMatch(res.similarity);
      } catch (err: any) {
        stopStream();
        onFail(err.message);
      }
    }

    if (descriptor) {
      verifyFace();
    }
  }, [descriptor, account, verifying, setDetecting, stopStream, onMatch, onFail]);

  return (
    <div className="card text-center" style={{ padding: "var(--space-6)" }}>
      <h3>Face Verification</h3>
      {error && <div className="alert alert-error">{error}</div>}
      <p className="text-muted mb-4">{verifying ? "Verifying match..." : status}</p>

      <div style={{ position: "relative", width: "100%", maxWidth: 400, margin: "0 auto", overflow: "hidden", borderRadius: 16, backgroundColor: "#000" }}>
        <video 
          ref={videoRef} 
          autoPlay 
          playsInline 
          muted 
          style={{ width: "100%", height: "auto", display: "block", transform: "scaleX(-1)" }}
        />
        <div style={{
          position: "absolute", top: "15%", left: "25%", right: "25%", bottom: "15%",
          border: `4px solid ${verifying ? "var(--color-primary-400)" : "rgba(255,255,255,0.4)"}`,
          borderRadius: "50%", boxShadow: "0 0 0 9999px rgba(0,0,0,0.5)",
          pointerEvents: "none", transition: "border-color 0.3s ease"
        }} />
      </div>

      {!modelsLoaded && !error && (
        <div style={{ marginTop: 20 }}><span className="spinner" /> Loading AI models</div>
      )}
    </div>
  );
}
