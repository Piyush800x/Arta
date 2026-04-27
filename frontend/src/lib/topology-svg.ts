interface Port { port: number; service: string; severity?: string; }

const SEV_COLOR: Record<string, string> = {
  critical: "#ff2d55", high: "#ff9500", medium: "#ffd60a",
  low: "#30d158", info: "#636366",
};

export function buildTopologySvg(targetIp: string, ports: Port[]): string {
  const cx = 400, cy = 300, r = 80;
  const nodeR = 42;
  const count = ports.length;

  if (count === 0) {
      return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600"
      style="width:100%;background:#080a0c;border-radius:6px;margin:16px 0">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="#0d1117" stroke="#00ff41" stroke-width="2"/>
      <text x="${cx}" y="${cy - 8}" text-anchor="middle"
        fill="#00ff41" font-size="11" font-family="Courier New" font-weight="700">TARGET</text>
      <text x="${cx}" y="${cy + 10}" text-anchor="middle"
        fill="#8b949e" font-size="9" font-family="Courier New">${targetIp}</text>
    </svg>`;
  }

  const nodes = ports.map((p, i) => {
    const angle   = (2 * Math.PI * i) / count - Math.PI / 2;
    const dist    = 200;
    const portNum = Number(p.port);
    return {
      ...p,
      port: isNaN(portNum) ? 0 : portNum,
      x: cx + dist * Math.cos(angle),
      y: cy + dist * Math.sin(angle),
    };
  });

  const lines = nodes.map(n =>
    `<line x1="${cx}" y1="${cy}" x2="${n.x}" y2="${n.y}"
      stroke="#30363d" stroke-width="1" stroke-dasharray="4 3"/>`
  ).join("");

  const circles = nodes.map(n => {
    const color = SEV_COLOR[n.severity ?? "info"] || SEV_COLOR.info;
    return `
      <circle cx="${n.x}" cy="${n.y}" r="${nodeR}" fill="#0d1117" stroke="${color}" stroke-width="2"/>
      <text x="${n.x}" y="${n.y - 6}" text-anchor="middle"
        fill="${color}" font-size="10" font-family="Courier New" font-weight="700">
        ${n.port > 0 ? `:${n.port}` : ""}
      </text>
      <text x="${n.x}" y="${n.y + 10}" text-anchor="middle"
        fill="#8b949e" font-size="9" font-family="Courier New">
        ${String(n.service).substring(0, 12)}
      </text>`;
  }).join("");

  return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600"
      style="width:100%;background:#080a0c;border-radius:6px;margin:16px 0">
      ${lines}
      <!-- Target node -->
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="#0d1117" stroke="#00ff41" stroke-width="2"/>
      <text x="${cx}" y="${cy - 8}" text-anchor="middle"
        fill="#00ff41" font-size="11" font-family="Courier New" font-weight="700">TARGET</text>
      <text x="${cx}" y="${cy + 10}" text-anchor="middle"
        fill="#8b949e" font-size="9" font-family="Courier New">${targetIp}</text>
      ${circles}
    </svg>`;
}
