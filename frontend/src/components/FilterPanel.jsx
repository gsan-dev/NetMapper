import { DEVICE_COLORS, DEVICE_LABELS } from "../deviceTypes";

function formatDate(ts) {
  return new Date(ts * 1000).toLocaleString();
}

const SECURITY_SOURCE_LABELS = {
  netguardian: "NetGuardian",
  "local-arp": "ARP/DHCP local",
};

/** Colapsa el histórico a solo los puntos donde cambió el tipo o el
 * fabricante — ver el mismo estado repetido en cada snapshot no aporta
 * nada, lo interesante es cuándo cambió. */
function deviceTypeTransitions(history) {
  const transitions = [];
  let lastKey = null;
  for (const entry of history) {
    const key = `${entry.device_type}|${entry.vendor || ""}`;
    if (key !== lastKey) {
      transitions.push(entry);
      lastKey = key;
    }
  }
  return transitions;
}

export default function FilterPanel({
  networks,
  subnetFilter,
  onSubnetChange,
  searchQuery = "",
  onSearchChange,
  layoutName,
  onLayoutChange,
  groupBySubnet,
  onGroupBySubnetChange,
  selectedDevice,
  deviceHistory = [],
}) {
  const transitions = deviceTypeTransitions(deviceHistory);
  const firstSeen = deviceHistory[0]?.created_at;
  return (
    <section className="panel filter-panel">
      <h2>Filtros</h2>

      <label className="field">
        Buscar
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="MAC, IP, fabricante, tipo..."
        />
      </label>

      <label className="field">
        Red
        <select value={subnetFilter} onChange={(e) => onSubnetChange(e.target.value)}>
          <option value="">Todas</option>
          {networks.map((n) => (
            <option key={n.cidr} value={n.cidr}>
              {n.cidr} {n.reachable ? "" : "· no escaneada"}
            </option>
          ))}
        </select>
      </label>

      <label className="field checkbox-field">
        <input
          type="checkbox"
          checked={groupBySubnet}
          onChange={(e) => onGroupBySubnetChange(e.target.checked)}
        />
        Agrupar por subred
      </label>

      <div className="field">
        Disposición
        <div className="button-group">
          <button
            className={layoutName === "hierarchical" ? "active" : ""}
            onClick={() => onLayoutChange("hierarchical")}
          >
            Jerárquica
          </button>
          <button
            className={layoutName === "force" ? "active" : ""}
            onClick={() => onLayoutChange("force")}
          >
            Force-directed
          </button>
        </div>
      </div>

      <div className="field">
        Leyenda
        <ul className="legend">
          {Object.entries(DEVICE_LABELS).map(([type, label]) => (
            <li key={type}>
              <span className="swatch" style={{ background: DEVICE_COLORS[type] }} />
              {label}
            </li>
          ))}
        </ul>
      </div>

      {selectedDevice && (
        <div className="field device-detail">
          Dispositivo seleccionado
          <dl>
            <dt>MAC</dt>
            <dd>{selectedDevice.id}</dd>
            <dt>IPs</dt>
            <dd>{selectedDevice.ips || "—"}</dd>
            <dt>Fabricante</dt>
            <dd>{selectedDevice.vendor}</dd>
            <dt>Tipo</dt>
            <dd>{DEVICE_LABELS[selectedDevice.deviceType] || selectedDevice.deviceType}</dd>
            <dt>Puertos abiertos</dt>
            <dd>{selectedDevice.openPorts}</dd>
            <dt>Estado</dt>
            <dd>
              {selectedDevice.isAuthorized === false ? (
                <span className="unauthorized-badge">⚠ No autorizado</span>
              ) : (
                "Autorizado"
              )}
            </dd>
            {selectedDevice.securityMaxSeverity && selectedDevice.securityMaxSeverity !== "none" && (
              <>
                <dt>Alertas de seguridad</dt>
                <dd>
                  <span className={`severity-badge severity-${selectedDevice.securityMaxSeverity}`}>
                    {selectedDevice.securityAlertCount} · {selectedDevice.securityMaxSeverity}
                  </span>
                  {" "}
                  <span className="security-source">
                    {SECURITY_SOURCE_LABELS[selectedDevice.securityAlertSource] || ""}
                  </span>
                  {selectedDevice.securityLastReason && (
                    <div className="security-reason">{selectedDevice.securityLastReason}</div>
                  )}
                </dd>
              </>
            )}
          </dl>

          {firstSeen && (
            <div className="device-history">
              <p className="first-seen">Visto por primera vez: {formatDate(firstSeen)}</p>
              {transitions.length > 1 && (
                <>
                  <p className="history-label">Historial de tipo/fabricante</p>
                  <ul className="history-list">
                    {transitions.map((t, i) => (
                      <li key={i}>
                        <span className="history-date">{formatDate(t.created_at)}</span>{" "}
                        {DEVICE_LABELS[t.device_type] || t.device_type}
                        {t.vendor ? ` — ${t.vendor}` : ""}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
