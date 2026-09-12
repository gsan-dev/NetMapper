import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import FilterPanel from "./components/FilterPanel";
import NetworkGraph from "./components/NetworkGraph";
import TimelapseControls from "./components/TimelapseControls";
import { connectWebSocket, fetchGraph, fetchNetworks, fetchSnapshots } from "./api";

const MAX_SNAPSHOTS = 200;

export default function App() {
  const [networks, setNetworks] = useState([]);
  const [liveDevices, setLiveDevices] = useState([]);
  const [liveRelations, setLiveRelations] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [selectedSnapshotIndex, setSelectedSnapshotIndex] = useState(0);
  const [live, setLive] = useState(true);
  const [subnetFilter, setSubnetFilter] = useState("");
  const [layoutName, setLayoutName] = useState("force");
  const [selectedDevice, setSelectedDevice] = useState(null);
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
    if (!subnetFilter) return devices;
    return devices.filter((d) => (d.subnet_cidrs || []).includes(subnetFilter));
  }, [devices, subnetFilter]);

  const unauthorizedCount = useMemo(
    () => filteredDevices.filter((d) => d.is_authorized === false).length,
    [filteredDevices]
  );

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
          layoutName={layoutName}
          onLayoutChange={setLayoutName}
          selectedDevice={selectedDevice}
        />

        <section className="panel graph-panel">
          <NetworkGraph
            ref={graphRef}
            devices={filteredDevices}
            relations={relations}
            layoutName={layoutName}
            onSelectDevice={setSelectedDevice}
          />
          {filteredDevices.length === 0 && (
            <p className="empty graph-empty">
              Sin dispositivos todavía. Arranca el pipeline (`python3 main.py --continuous`
              dentro de discovery/) para empezar a ver tu red.
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
