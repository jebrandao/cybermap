// Traduz as chaves de "threatfeeds" retornadas por api/ip/{ip} do DShield
// (listas de reputacao de terceiros que ja flagraram aquele IP) em rotulos
// legiveis. Isso e dado real (o IP realmente aparece nessas listas), nao
// uma classificacao inferida -- ao contrario do attackType, que e sorteado
// por porta (ver attack-types.mjs).
import { describePort } from "./attack-types.mjs";

const FEED_LABELS = {
  ciarmy: "CI Army — host malicioso confirmado",
  recyber: "ReCyber — lista de ameacas",
  emergincompromised: "Emerging Threats — host comprometido",
  spamhaus_drop: "Spamhaus DROP — rede maliciosa",
  spamhaus_edrop: "Spamhaus EDROP — rede maliciosa",
  malc0de: "Malc0de — distribuicao de malware",
  botscout: "BotScout — bot conhecido",
  nixspam: "NiX Spam — fonte de spam",
  greensnow: "GreenSnow — atividade maliciosa",
  bruteforceblocker: "BruteForceBlocker — forca bruta",
  tornode: "No de saida Tor",
  tor: "No de saida Tor",
  alienvault: "AlienVault OTX",
  miner: "Atividade de mineracao de criptomoeda",
  myip: "Servico de IP publico",
  openresolver: "Resolvedor DNS aberto",
  sshpwauth: "Forca bruta SSH (DShield)",
  openbl: "OpenBL — abuso reportado",
  openbl_ssh: "OpenBL — forca bruta SSH",
  openbl_smtp: "OpenBL — abuso SMTP",
  dshield: "Lista DShield",
};

const BLOCKLISTDE_SUFFIX_LABELS = {
  apache: "Apache",
  asterisk: "Asterisk/VoIP",
  bruteforcelogin: "login por forca bruta",
  courierimap: "IMAP (Courier)",
  ftp: "FTP",
  mail: "e-mail",
  sip: "SIP",
  strongips: "IP recorrente",
};

export function describeFeed(key) {
  if (FEED_LABELS[key]) return FEED_LABELS[key];

  if (key.startsWith("blocklistde")) {
    const suffix = key.slice("blocklistde".length);
    const portNum = Number(suffix);
    if (suffix && !Number.isNaN(portNum)) {
      return `Blocklist.de — ${describePort(portNum).label}`;
    }
    return `Blocklist.de — ${BLOCKLISTDE_SUFFIX_LABELS[suffix] || suffix}`;
  }

  // Fallback: humaniza a chave crua em vez de escondê-la.
  return key.replace(/_/g, " ");
}

// Pega as entradas mais recentes de threatfeeds (objeto {chave: {firstseen,
// lastseen}}) e devolve os rotulos prontos para exibir, mais recentes primeiro.
export function buildThreatTags(threatfeeds, limit = 3) {
  if (!threatfeeds) return [];
  return Object.entries(threatfeeds)
    .sort((a, b) => new Date(b[1]?.lastseen || 0) - new Date(a[1]?.lastseen || 0))
    .slice(0, limit)
    .map(([key, meta]) => ({
      key,
      label: describeFeed(key),
      lastSeen: meta?.lastseen || null,
    }));
}
