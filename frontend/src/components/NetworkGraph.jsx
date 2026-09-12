import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";
import { colorForType } from "../deviceTypes";

function buildElements(devices, relations) {
  const nodes = devices.map((d) => ({
    data: {
      id: d.mac,
      label: d.ips?.[0] || d.mac,
      deviceType: d.device_type,
      vendor: d.vendor || "Fabricante desconocido",
      ips: (d.ips || []).join(", "),
      openPorts: (d.open_ports || []).join(", ") || "ninguno detectado",
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

const STYLE = [
  {
    selector: "node",
    style: {
      "background-color": (ele) => colorForType(ele.data("deviceType")),
      label: "data(label)",
      "font-size": 9,
      color: "#cbd5e1",
      "text-valign": "bottom",
      "text-margin-y": 6,
      "text-outline-width": 0,
      width: 28,
      height: 28,
      "border-width": 2,
      "border-color": "#0f172a",
    },
  },
  {
    selector: "node:selected",
    style: {
      "border-width": 3,
      "border-color": "#f8fafc",
    },
  },
  {
    selector: "edge",
    style: {
      width: (ele) => Math.min(8, 1 + Math.log10(1 + (ele.data("bytesTotal") || 0))),
      "line-color": "#334155",
      "target-arrow-shape": "none",
      "curve-style": "haystack",
      opacity: 0.55,
    },
  },
];

export default function NetworkGraph({ devices, relations, layoutName, onSelectDevice }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return undefined;

    const cy = cytoscape({
      container: containerRef.current,
      elements: buildElements(devices, relations),
      style: STYLE,
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
  }, [devices, relations, layoutName]);

  return <div ref={containerRef} className="graph-canvas" />;
}
