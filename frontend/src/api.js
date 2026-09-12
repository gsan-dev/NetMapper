/**
 * Cliente API de NetMapper: REST + WebSocket en tiempo real.
 */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8100";
const WS_BASE_URL = API_BASE_URL.replace(/^http/, "ws");

async function getJson(path) {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    throw new Error(`Error ${response.status} llamando a ${path}`);
  }
  return response.json();
}

export function fetchNetworks() {
  return getJson("/api/networks");
}

export function fetchDevices(activeOnly = true) {
  return getJson(`/api/devices?active_only=${activeOnly}`);
}

export function fetchGraph() {
  return getJson("/api/graph");
}

export function fetchSnapshots(limit = 100) {
  return getJson(`/api/graph/snapshots?limit=${limit}`);
}

export function connectWebSocket({ onMessage, onOpen, onClose }) {
  const ws = new WebSocket(`${WS_BASE_URL}/ws`);
  ws.onopen = () => onOpen && onOpen();
  ws.onclose = () => onClose && onClose();
  ws.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      onMessage && onMessage(message);
    } catch (err) {
      console.error("Mensaje de WebSocket inválido", err);
    }
  };
  return ws;
}
