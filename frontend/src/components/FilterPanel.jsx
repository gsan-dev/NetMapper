import { DEVICE_COLORS, DEVICE_LABELS } from "../deviceTypes";

export default function FilterPanel({
  networks,
  subnetFilter,
  onSubnetChange,
  layoutName,
  onLayoutChange,
  selectedDevice,
}) {
  return (
    <section className="panel filter-panel">
      <h2>Filtros</h2>

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
          </dl>
        </div>
      )}
    </section>
  );
}
