import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import FilterPanel from "./components/FilterPanel";
import NetworkGraph from "./components/NetworkGraph";
import TimelapseControls from "./components/TimelapseControls";
import {
  connectWebSocket,
  fetchDeviceHistory,
  fetchGraph,
  fetchNetworks,
  fetchSnapshots,
} from "./api";

const MAX_SNAPSHOTS = 200;

export default function App() {
  const [networks, setNetworks] = useState([]);
  const [liveDevices, setLiveDevices] = useState([]);
  const [liveRelations, setLiveRelations] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [selectedSnapshotIndex, setSelectedSnapshotIndex] = useState(0);
  const [live, setLive] = useState(true);
  const [subnetFilter, setSubnetFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("netmapper_theme") || "dark";
    } catch {
      return "dark";
    }
  });
  const [layoutName, setLayoutName] = useState("force");
  const [groupBySubnet, setGroupBySubnet] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [deviceHistory, setDeviceHistory] = useState([]);
  const [wsStatus, setWsStatus] = useState("desconectado");
  const wsRef = useRef(null);
  const graphRef = useRef(null);

  const loadInitialData = useCallback(async () => {
    const [networksData, graphData, snapshotsData] = await Promise.all([
      fetchNetworks(),
      fetchGraph(),
      fetchSnapshots(MAX_SNAPSHOTS),
    ]);
    setNetworks(networksData);
    setLiveDevices(graphData.devices);
    setLiveRelations(graphData.relations);
    setSnapshots(snapshotsData);
    setSelectedSnapshotIndex(Math.max(0, snapshotsData.length - 1));
  }, []);

  useEffect(() => {
    loadInitialData().catch((err) => console.error("Error cargando datos iniciales", err));

    const ws = connectWebSocket({
      onOpen: () => setWsStatus("conectado"),
      onClose: () => setWsStatus("desconectado"),
      onMessage: (message) => {
        if (message.type === "graph_update") {
          setLiveDevices(message.data.devices);
          setLiveRelations(message.data.relations);
        }
      },
    });
    wsRef.current = ws;
    return () => ws.close();
  }, [loadInitialData]);

  const { devices, relations } = useMemo(() => {
    if (live) {
      return { devices: liveDevices, relations: liveRelations };
    }
    const snapshot = snapshots[selectedSnapshotIndex];
    if (!snapshot) return { devices: [], relations: [] };
    return { devices: snapshot.devices, relations: snapshot.relations };
  }, [live, liveDevices, liveRelations, snapshots, selectedSnapshotIndex]);

  const filteredDevices = useMemo(() => {
    let result = devices;
    if (subnetFilter) {
      result = result.filter((d) => (d.subnet_cidrs || []).includes(subnetFilter));
    }
    const query = searchQuery.trim().toLowerCase();
    if (query) {
      result = result.filter((d) => {
        const haystack = [
          d.mac,
          d.vendor,
          d.device_type,
          ...(d.ips || []),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(query);
      });
    }
    return result;
  }, [devices, subnetFilter, searchQuery]);

  const unauthorizedCount = useMemo(
    () => filteredDevices.filter((d) => d.is_authorized === false).length,
    [filteredDevices]
  );

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("netmapper_theme", theme);
    } catch {
      // localStorage puede no estar disponible (modo privado); no es crítico
    }
  }, [theme]);

  useEffect(() => {
    if (!selectedDevice) {
      setDeviceHistory([]);
      return;
    }
    let cancelled = false;
    fetchDeviceHistory(selectedDevice.id)
      .then((history) => {
        if (!cancelled) setDeviceHistory(history);
      })
      .catch((err) => console.error("Error cargando histórico del dispositivo", err));
    return () => {
      cancelled = true;
    };
  }, [selectedDevice]);

  function downloadDataUrl(dataUrl, filename) {
    const a = document.createElement("a");
    a.href = dataUrl;
    a.download = filename;
    a.click();
  }

  function handleExportPng() {
    const dataUrl = graphRef.current?.exportPng();
    if (dataUrl) downloadDataUrl(dataUrl, "netmapper-mapa.png");
  }

  function handleExportGraphml() {
    const xml = graphRef.current?.exportGraphml();
    if (!xml) return;
    const url = URL.createObjectURL(new Blob([xml], { type: "application/xml" }));
    downloadDataUrl(url, "netmapper-mapa.graphml");
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>🗺️ NetMapper</h1>
          <span className={`ws-badge ${wsStatus === "conectado" ? "ws-on" : "ws-off"}`}>
            {wsStatus === "conectado" ? "● conectado" : "○ sin conexión"}
          </span>
        </div>
        <div className="topbar-stats">
          <span>{filteredDevices.length} dispositivos</span>
          <span>{relations.length} relaciones</span>
          <span>{networks.length} redes</span>
          {unauthorizedCount > 0 && (
            <span className="unauthorized-badge">⚠ {unauthorizedCount} no autorizado(s)</span>
          )}
        </div>
        <div className="topbar-actions">
          <button onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}>
            {theme === "dark" ? "☀ Claro" : "🌙 Oscuro"}
          </button>
          <button onClick={handleExportPng}>Exportar PNG</button>
          <button onClick={handleExportGraphml} title="Importable en draw.io: File > Import from > Device">
            Exportar GraphML
          </button>
        </div>
      </header>

      <main className="dashboard">
        <FilterPanel
          networks={networks}
          subnetFilter={subnetFilter}
          onSubnetChange={setSubnetFilter}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          layoutName={layoutName}
          onLayoutChange={setLayoutName}
          groupBySubnet={groupBySubnet}
          onGroupBySubnetChange={setGroupBySubnet}
          selectedDevice={selectedDevice}
          deviceHistory={deviceHistory}
        />

        <section className="panel graph-panel">
          <NetworkGraph
            ref={graphRef}
            devices={filteredDevices}
            relations={relations}
            layoutName={layoutName}
            theme={theme}
            groupBySubnet={groupBySubnet}
            onSelectDevice={setSelectedDevice}
          />
          {filteredDevices.length === 0 && devices.length === 0 && (
            <p className="empty graph-empty">
              Sin dispositivos todavía. Arranca el pipeline (`python3 main.py --continuous`
              dentro de discovery/) para empezar a ver tu red.
            </p>
          )}
          {filteredDevices.length === 0 && devices.length > 0 && (
            <p className="empty graph-empty">
              Ningún dispositivo coincide con el filtro/búsqueda actual.
            </p>
          )}
        </section>

        <TimelapseControls
          snapshots={snapshots}
          selectedIndex={selectedSnapshotIndex}
          onSelect={setSelectedSnapshotIndex}
          live={live}
          onToggleLive={() => setLive((prev) => !prev)}
        />
      </main>
    </div>
  );
}
