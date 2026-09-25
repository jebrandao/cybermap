// Mapeia porta de destino -> tipo de ataque/servico + categoria.
// Baseado em associacoes de portas bem conhecidas (nao e uma classificacao
// oficial da DShield, ja que a API nao expoe "tipo de ataque" por evento).
export const PORT_ATTACK_TYPES = {
  20: { label: "FTP Data Scan", category: "remote" },
  21: { label: "FTP Brute-force", category: "remote" },
  22: { label: "SSH Brute-force", category: "remote" },
  23: { label: "Telnet / IoT Botnet", category: "remote" },
  25: { label: "SMTP Spam Relay", category: "mail" },
  53: { label: "DNS Scan", category: "net" },
  80: { label: "HTTP Scan", category: "web" },
  110: { label: "POP3 Brute-force", category: "mail" },
  135: { label: "RPC Scan", category: "net" },
  139: { label: "NetBIOS Scan", category: "net" },
  143: { label: "IMAP Brute-force", category: "mail" },
  389: { label: "LDAP Scan", category: "net" },
  443: { label: "HTTPS Scan", category: "web" },
  445: { label: "SMB Exploit (EternalBlue)", category: "remote" },
  465: { label: "SMTPS Scan", category: "mail" },
  587: { label: "SMTP Submission Scan", category: "mail" },
  853: { label: "DNS-over-TLS Scan", category: "net" },
  993: { label: "IMAPS Brute-force", category: "mail" },
  995: { label: "POP3S Brute-force", category: "mail" },
  1433: { label: "MSSQL Brute-force", category: "db" },
  1521: { label: "Oracle DB Scan", category: "db" },
  1723: { label: "PPTP VPN Scan", category: "remote" },
  2222: { label: "SSH Scan (porta alt.)", category: "remote" },
  3306: { label: "MySQL Brute-force", category: "db" },
  3389: { label: "RDP Brute-force", category: "remote" },
  5060: { label: "SIP/VoIP Scan", category: "net" },
  5432: { label: "PostgreSQL Scan", category: "db" },
  5900: { label: "VNC Brute-force", category: "remote" },
  6379: { label: "Redis Exposto", category: "db" },
  8000: { label: "HTTP Alt Scan", category: "web" },
  8080: { label: "HTTP Proxy Scan", category: "web" },
  8443: { label: "HTTPS Alt Scan", category: "web" },
  9200: { label: "Elasticsearch Exposto", category: "db" },
  27017: { label: "MongoDB Exposto", category: "db" },
};

export const CATEGORY_COLORS = {
  web: "#33e0ff",
  remote: "#ff3366",
  db: "#c792ea",
  mail: "#ffd166",
  net: "#4ade80",
  other: "#94a3b8",
};

export const CATEGORY_LABELS = {
  web: "Web (HTTP/HTTPS)",
  remote: "Acesso remoto (SSH/RDP/Telnet)",
  db: "Banco de dados",
  mail: "E-mail",
  net: "Rede / DNS",
  other: "Outro",
};

// Ordem fixa de exibicao na legenda.
export const CATEGORY_ORDER = ["web", "remote", "db", "mail", "net", "other"];

export function describePort(port) {
  return (
    PORT_ATTACK_TYPES[port] || {
      label: `Varredura porta ${port}`,
      category: "other",
    }
  );
}

// Sorteia uma porta entre as top portas do dia, com probabilidade
// proporcional ao numero de fontes (sources) reportadas para cada uma.
// A API nao associa porta a IP especifico nas listagens de top atacantes,
// entao usamos a distribuicao agregada real do dia como proxy.
export function pickWeightedPort(topPorts) {
  const weights = topPorts.map((p) => Math.max(1, p.sources || 1));
  const total = weights.reduce((a, b) => a + b, 0);
  let r = Math.random() * total;
  for (let i = 0; i < topPorts.length; i++) {
    r -= weights[i];
    if (r <= 0) return topPorts[i].port;
  }
  return topPorts[topPorts.length - 1].port;
}
