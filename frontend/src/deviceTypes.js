/**
 * Colores por tipo de dispositivo — refleja common/device_types.py.
 * Centralizado aquí para que NetworkGraph y FilterPanel (leyenda)
 * usen exactamente la misma paleta.
 */
export const DEVICE_COLORS = {
  router: "#f59e0b",
  switch: "#eab308",
  nas: "#22c55e",
  ip_camera: "#ef4444",
  printer: "#a78bfa",
  server: "#38bdf8",
  mobile: "#ec4899",
  iot: "#14b8a6",
  unknown: "#94a3b8",
};

export const DEVICE_LABELS = {
  router: "Router",
  switch: "Switch",
  nas: "NAS",
  ip_camera: "Cámara IP",
  printer: "Impresora",
  server: "Servidor",
  mobile: "Móvil",
  iot: "IoT",
  unknown: "Desconocido",
};

export function colorForType(deviceType) {
  return DEVICE_COLORS[deviceType] || DEVICE_COLORS.unknown;
}
