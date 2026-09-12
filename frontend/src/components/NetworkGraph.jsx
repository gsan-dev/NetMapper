import cytoscape from "cytoscape";
import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import { colorForType } from "../deviceTypes";

// Color del halo de alerta de seguridad (integración con NetGuardian).
const SEVERITY_HALO_COLOR = {
  low: "#fbbf24",
  medium: "#f97316",
  high: "#ef4444",
};

function cssVar(name, fallback) {
  if (typeof window === "undefined") return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

function escapeXml(value) {
  return String(value ?? "").replace(/[<>&'"]/g, (c) => ({
    "<": "&lt;",
    ">": "&gt;",
    "&": "&amp;",
    "'": "&apos;",
    '"': "&quot;",
  })[c]);
}

function buildElements(devices, relations) {
  const nodes = devices.map((d) => ({
    data: {
      id: d.mac,
      label: d.ips?.[0] || d.mac,
      deviceType: d.device_type,
      vendor: d.vendor || "Fabricante desconocido",
      ips: (d.ips || []).join(", "),
      openPorts: (d.open_ports || []).join(", ") || "ninguno detectado",
      // false solo cuando el backend lo marca explícitamente (whitelist
      // ALLOWED_DEVICES configurada); si el campo no viene, se asume
      // autorizado para no pintar de "sospechoso" datos antiguos/parciales.
      isAuthorized: d.is_authorized !== false,
      // Integración con NetGuardian: severidad máxima de alerta reciente.
      securityMaxSeverity: d.security_max_severity || "none",
      securityAlertCount: d.security_alert_count || 0,
      securityLastReason: d.security_last_reason,
    },
  }));

  const nodeIds = new Set(nodes.map((n) => n.data.id));
  const edges = relations
    .filter((r) => nodeIds.has(r.src_mac) && nodeIds.has(r.dst_mac) && r.src_mac !== r.dst_mac)
    .map((r) => ({
      data: {
        id: `${r.src_mac}->${r.dst_mac}`,
        source: r.src_mac,
        target: r.dst_mac,
        bytesTotal: r.bytes_total,
      },
    }));

  return [...nodes, ...edges];
}

// Los colores base (fondo del nodo por tipo, halo de severidad) son
// semánticos y se mantienen fijos entre temas; los que dependen del
// fondo del lienzo (texto, borde, aristas) se leen de las custom
// properties de CSS para que el grafo seepa qué tema está activo —
// Cytoscape no hereda CSS, así que esto se recalcula al reconstruir el
// grafo (ver el efecto más abajo, que incluye `theme` en sus deps).
function buildStyle() {
  const label = cssVar("--graph-label", "#cbd5e1");
  const nodeBorder = cssVar("--graph-node-border", "#0f172a");
  const edgeColor = cssVar("--graph-edge", "#334155");
  const accent = cssVar("--accent", "#38bdf8");

  return [
    {
      selector: "node",
      style: {
        "background-color": (ele) => colorForType(ele.data("deviceType")),
        label: "data(label)",
        "font-size": 9,
        color: label,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-outline-width": 0,
        width: 28,
        height: 28,
        "border-width": (ele) => (ele.data("isAuthorized") === false ? 3 : 2),
        "border-color": (ele) => (ele.data("isAuthorized") === false ? "#ef4444" : nodeBorder),
        "border-style": (ele) => (ele.data("isAuthorized") === false ? "dashed" : "solid"),
        // Halo de alerta de seguridad (integración con NetGuardian): un
        // anillo de color alrededor del nodo, sin ocultar su color de tipo.
        "overlay-color": (ele) =>
          SEVERITY_HALO_COLOR[ele.data("securityMaxSeverity")] || "transparent",
        "overlay-opacity": (ele) => (SEVERITY_HALO_COLOR[ele.data("securityMaxSeverity")] ? 0.4 : 0),
        "overlay-padding": 6,
      },
    },
    {
      selector: "node:selected",
      style: {
        "border-width": 3,
        "border-color": accent,
      },
    },
    {
      selector: "edge",
      style: {
        width: (ele) => Math.min(8, 1 + Math.log10(1 + (ele.data("bytesTotal") || 0))),
        "line-color": edgeColor,
        "target-arrow-shape": "none",
        "curve-style": "haystack",
        opacity: 0.55,
      },
    },
  ];
}

const NetworkGraph = forwardRef(function NetworkGraph(
  { devices, relations, layoutName, theme, onSelectDevice },
  ref
) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useImperativeHandle(ref, () => ({
    exportPng: () =>
      cyRef.current?.png({ full: true, scale: 2, bg: cssVar("--graph-bg", "#0f172a") }),
    exportGraphml: () => {
      const cy = cyRef.current;
      if (!cy) return "";

      const nodesXml = cy
        .nodes()
        .map(
          (n) =>
            `    <node id="${escapeXml(n.id())}"><data key="label">${escapeXml(
              n.data("label")
            )}</data></node>`
        )
        .join("\n");

      const edgesXml = cy
        .edges()
        .map(
          (e) =>
            `    <edge source="${escapeXml(e.data("source"))}" target="${escapeXml(
              e.data("target")
            )}"/>`
        )
        .join("\n");

      return (
        '<?xml version="1.0" encoding="UTF-8"?>\n' +
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n' +
        '  <key id="label" for="node" attr.name="label" attr.type="string"/>\n' +
        '  <graph id="NetMapper" edgedefault="undirected">\n' +
        `${nodesXml}\n${edgesXml}\n` +
        "  </graph>\n</graphml>\n"
      );
    },
  }));

  useEffect(() => {
    if (!containerRef.current) return undefined;

    const cy = cytoscape({
      container: containerRef.current,
      elements: buildElements(devices, relations),
      style: buildStyle(),
      layout: {
        // animate:false a propósito: con animate:true, si React StrictMode
        // desmonta y remonta el componente en desarrollo mientras la
        // animación del layout sigue en curso, el callback de la animación
        // intenta notificar a una instancia de Cytoscape ya destruida
        // (TypeError: Cannot read properties of null, reading 'notify').
        name: layoutName === "hierarchical" ? "breadthfirst" : "cose",
        animate: false,
        fit: true,
        padding: 24,
      },
      minZoom: 0.2,
      maxZoom: 3,
    });

    cy.on("tap", "node", (evt) => {
      onSelectDevice && onSelectDevice(evt.target.data());
    });

    cyRef.current = cy;
    return () => cy.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [devices, relations, layoutName, theme]);

  return <div ref={containerRef} className="graph-canvas" />;
});

export default NetworkGraph;
