export async function syncDeviceTime(): Promise<{ ok: boolean; error?: string }> {
  try {
    if (!navigator.bluetooth) {
      return { ok: false, error: "Web Bluetooth is not supported in this browser." };
    }

    const SERVICE_UUID = '4e67a200-1234-5678-abcd-0123456789ab';
    const CHARACTERISTIC_UUID = '4e67a201-1234-5678-abcd-0123456789ab';

    const device = await navigator.bluetooth.requestDevice({
      filters: [{ namePrefix: 'AttendESP_' }],
      optionalServices: [SERVICE_UUID]
    });

    if (!device.gatt) {
      return { ok: false, error: "GATT server is unavailable on this device." };
    }

    const server = await device.gatt.connect();

    try {
      const service = await server.getPrimaryService(SERVICE_UUID);
      const characteristic = await service.getCharacteristic(CHARACTERISTIC_UUID);

      const currentTimeSeconds = Math.floor(Date.now() / 1000).toString();
      const encoder = new TextEncoder();
      const data = encoder.encode(currentTimeSeconds);

      await characteristic.writeValue(data);
      
    } finally {
      // Always ensure we disconnect even if service/characteristic lookup fails
      if (server.connected) {
        server.disconnect();
      }
    }

    return { ok: true };

  } catch (err: any) {
    console.error("Time sync error:", err);
    if (err.name === 'NotFoundError') {
      return { ok: false, error: "Scan cancelled by user." };
    } else if (err.name === 'NetworkError') {
      return { ok: false, error: "GATT connection failed. Device may be out of range." };
    }
    return { ok: false, error: err.message || "Failed to sync time to the device." };
  }
}
