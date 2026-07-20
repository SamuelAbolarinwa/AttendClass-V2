import { useState, useEffect, useRef } from "react";
import { syncDeviceTime } from "../lib/syncDeviceTime";

export interface BleCheckinResult {
  rssi: number;
  deviceId: string; // The short code as a string
  token: string;
}

export interface BleCheckinProps {
  onSuccess: (result: BleCheckinResult) => void;
  onFailure: (reason: string) => void;
}

export function BleCheckinFlow({ onSuccess, onFailure }: BleCheckinProps) {
  const [status, setStatus] = useState("Click 'Start Scan' to search for your class ESP32 beacon.");
  const [scanning, setScanning] = useState(false);
  const [unsupported, setUnsupported] = useState(false);
  const [timeoutOccurred, setTimeoutOccurred] = useState(false);
  const [syncLoading, setSyncLoading] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    // Check basic Bluetooth availability
    if (!navigator.bluetooth) {
      setUnsupported(true);
    }
    
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const handleStartScan = async () => {
    try {
      if (!navigator.bluetooth) {
        throw new Error("Web Bluetooth is not supported in this browser.");
      }

      setScanning(true);
      setTimeoutOccurred(false);
      setSyncError(null);
      setStatus("Requesting Bluetooth permissions...");

      const device = await navigator.bluetooth.requestDevice({
        filters: [{ namePrefix: 'AttendESP_' }],
        optionalManufacturerData: [0xFFFF]
      });

      setStatus("Connecting and waiting for broadcast...");

      if (typeof device.watchAdvertisements !== 'function') {
        throw new Error("watchAdvertisements is not supported. Please enable #enable-experimental-web-platform-features and #enable-web-bluetooth-new-permissions-backend in chrome://flags");
      }

      abortControllerRef.current = new AbortController();

      const timeoutId = setTimeout(() => {
        if (abortControllerRef.current) {
          abortControllerRef.current.abort();
        }
        setScanning(false);
        setTimeoutOccurred(true);
        setStatus("Timed out waiting for BLE broadcast.");
      }, 15000);

      device.addEventListener('advertisementreceived', (event: any) => {
        const manufacturerData = event.manufacturerData;
        if (!manufacturerData || !manufacturerData.has(0xFFFF)) return;

        const dataView = manufacturerData.get(0xFFFF) as DataView;
        if (dataView.byteLength < 7) return;

        clearTimeout(timeoutId);
        if (abortControllerRef.current) {
          abortControllerRef.current.abort();
        }

        // Bytes 0-3: device short code (uint32 big-endian)
        const shortCode = dataView.getUint32(0, false).toString();

        // Bytes 4-6: 6-digit TOTP packed as BCD
        let token = "";
        for (let i = 4; i < 7; i++) {
          const byte = dataView.getUint8(i);
          const high = (byte >> 4) & 0x0F;
          const low = byte & 0x0F;
          token += high.toString() + low.toString();
        }

        const rssi = event.rssi;

        setScanning(false);
        setStatus("Broadcast received! Verifying...");
        onSuccess({ rssi, deviceId: shortCode, token });
      }, { once: true, signal: abortControllerRef.current.signal });

      await device.watchAdvertisements({ signal: abortControllerRef.current.signal });

    } catch (err: any) {
      setScanning(false);
      console.error(err);
      if (err.name === 'NotFoundError') {
        // User cancelled the picker
        setStatus("Scan cancelled by user.");
      } else {
        onFailure(err.message || "Failed to connect to BLE device.");
      }
    }
  };

  const handleSyncTime = async () => {
    setSyncLoading(true);
    setSyncError(null);
    setStatus("Syncing device time via GATT...");

    const res = await syncDeviceTime();
    setSyncLoading(false);

    if (res.ok) {
      setStatus("Time synced successfully! Retrying scan...");
      setTimeoutOccurred(false);
      handleStartScan(); // Auto-retry
    } else {
      setSyncError(res.error || "Failed to sync time.");
      setStatus("Time sync failed. You can try scanning again.");
    }
  };

  if (unsupported) {
    return (
      <div className="card text-center" style={{ padding: "var(--space-8)", borderColor: "var(--color-error)" }}>
        <div style={{ fontSize: "3rem", marginBottom: "var(--space-4)" }}>⚠️</div>
        <h3>Browser Unsupported</h3>
        <p className="text-muted mb-4">
          Your browser does not support Web Bluetooth. Please try Chrome on Android or Desktop. 
        </p>
      </div>
    );
  }

  return (
    <div className="card text-center" style={{ padding: "var(--space-8)" }}>
      <div style={{ fontSize: "3rem", marginBottom: "var(--space-4)" }}>📡</div>
      <h3>BLE Verification Step</h3>
      <p className="text-muted mb-4">{status}</p>
      
      {!scanning && !timeoutOccurred && (
        <button className="btn btn-primary btn-lg" onClick={handleStartScan}>
          Start Scan
        </button>
      )}
      
      {scanning && (
        <div style={{ marginTop: 20 }}>
          <span className="spinner" style={{ width: 24, height: 24, display: 'inline-block', borderWidth: 3 }} />
        </div>
      )}

      {!scanning && timeoutOccurred && (
        <div className="flex gap-2" style={{ flexDirection: "column", alignItems: "center" }}>
          <button className="btn btn-primary btn-lg" onClick={handleStartScan} disabled={syncLoading}>
            Retry Scan
          </button>
          
          <div style={{ marginTop: "var(--space-4)", paddingTop: "var(--space-4)", borderTop: "1px solid var(--color-border)", width: "100%" }}>
            <p className="text-xs text-muted mb-2">Only needed if the device's clock isn't set yet.</p>
            <button className="btn btn-secondary btn-sm" onClick={handleSyncTime} disabled={syncLoading}>
              {syncLoading ? <span className="spinner" /> : "Sync Device Time"}
            </button>
            {syncError && (
              <p className="text-xs text-error mt-2" style={{ fontWeight: 500 }}>{syncError}</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
