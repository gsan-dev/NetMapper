function formatDate(ts) {
  return new Date(ts * 1000).toLocaleString();
}

export default function TimelapseControls({ snapshots, selectedIndex, onSelect, live, onToggleLive }) {
  if (snapshots.length === 0) {
    return (
      <section className="panel timelapse">
        <h2>Time-lapse</h2>
        <p className="empty">Todavía no hay histórico de análisis del grafo.</p>
      </section>
    );
  }

  const snapshot = snapshots[selectedIndex] ?? snapshots[snapshots.length - 1];

  return (
    <section className="panel timelapse">
      <h2>
        Time-lapse
        <button className={`live-toggle ${live ? "on" : ""}`} onClick={onToggleLive}>
          {live ? "● En vivo" : "○ Histórico"}
        </button>
      </h2>
      <input
        type="range"
        min={0}
        max={snapshots.length - 1}
        value={selectedIndex}
        disabled={live}
        onChange={(e) => onSelect(Number(e.target.value))}
      />
      <p className="timelapse-caption">
        {formatDate(snapshot.created_at)} — {snapshot.node_count} dispositivos,{" "}
        {snapshot.edge_count} relaciones
      </p>
    </section>
  );
}
