#!/usr/bin/env node
// Coleta dados de ataques do DShield (SANS ISC) e gera data/attacks.json
// Uso: node scripts/fetch-dshield.mjs
//
// Documentacao da API: https://isc.sans.edu/api/
// A API nao exige chave, mas pede um User-Agent identificando a ferramenta
// e um contato. Ajuste CONTACT abaixo antes de publicar/agendar este script.

import { writeFile, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  describePort,
  pickWeightedPort,
  CATEGORY_COLORS,
  CATEGORY_LABELS,
  CATEGORY_ORDER,
} from "./attack-types.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, "..", "data");

const CONTACT = process.env.DSHIELD_CONTACT || "github.com/SEU_USUARIO/SEU_REPO";
const USER_AGENT = `cybermap-clone (+${CONTACT})`;

const TOP_IPS_LIMIT = Number(process.env.TOP_IPS_LIMIT || 20);
const TOP_PORTS_LIMIT = Number(process.env.TOP_PORTS_LIMIT || 10);
const CVE_LIMIT = Number(process.env.CVE_LIMIT || 8);
const REQUEST_DELAY_MS = 400;

const SEVERITY_COLORS = {
  CRITICAL: "#ff3366",
  HIGH: "#ff8c42",
  MEDIUM: "#ffd166",
  LOW: "#4ade80",
  NONE: "#94a3b8",
};

// Pontos-alvo estilizados: a API do DShield nao informa a localizacao real
// dos sensores/alvos (por privacidade), entao usamos alguns hubs fixos so
// para dar direcao visual aos arcos, sem alegar precisao geografica real.
const TARGET_HUBS = [
  { name: "US-Washington", coord: [-77.03, 38.9], country: "US" },
  { name: "DE-Frankfurt", coord: [8.68, 50.11], country: "DE" },
  { name: "NL-Amsterdam", coord: [4.9, 52.37], country: "NL" },
  { name: "GB-London", coord: [-0.13, 51.51], country: "GB" },
  { name: "FR-Paris", coord: [2.35, 48.86], country: "FR" },
  { name: "JP-Tokyo", coord: [139.69, 35.68], country: "JP" },
  { name: "SG-Singapore", coord: [103.82, 1.35], country: "SG" },
  { name: "IN-Mumbai", coord: [72.88, 19.08], country: "IN" },
  { name: "BR-SaoPaulo", coord: [-46.63, -23.55], country: "BR" },
  { name: "AU-Sydney", coord: [151.21, -33.87], country: "AU" },
  { name: "CA-Toronto", coord: [-79.38, 43.65], country: "CA" },
  { name: "KR-Seoul", coord: [126.98, 37.57], country: "KR" },
];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJSON(url, { retries = 2 } = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const res = await fetch(url, {
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
    });
    if (res.status === 429) {
      const retryAfter = Number(res.headers.get("retry-after")) || 30;
      console.warn(`429 recebido, aguardando ${retryAfter}s...`);
      await sleep(retryAfter * 1000);
      continue;
    }
    if (!res.ok) {
      throw new Error(`Falha em ${url}: HTTP ${res.status}`);
    }
    return res.json();
  }
  throw new Error(`Falha em ${url} apos ${retries} tentativas`);
}

async function loadCentroids() {
  const raw = await readFile(join(DATA_DIR, "country-centroids.json"), "utf8");
  return JSON.parse(raw);
}

function jitterAround([lon, lat], spreadDeg = 4) {
  return [
    lon + (Math.random() - 0.5) * spreadDeg,
    lat + (Math.random() - 0.5) * spreadDeg,
  ];
}

function isoDaysAgo(days) {
  const d = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return d.toISOString().replace("Z", "");
}

// Busca CVEs publicados recentemente na NVD (NIST). Isso NAO tem relacao
// direta com os eventos de ataque do DShield mostrados no mapa -- e uma
// lista informativa de vulnerabilidades recem-divulgadas, nao uma
// atribuicao "este ataque explora este CVE".
async function fetchRecentCVEs(limit) {
  const url =
    `https://services.nvd.nist.gov/rest/json/cves/2.0` +
    `?pubStartDate=${isoDaysAgo(5)}&pubEndDate=${isoDaysAgo(0)}` +
    `&resultsPerPage=200`;

  let data;
  try {
    data = await fetchJSON(url);
  } catch (err) {
    console.warn(`Falha ao buscar CVEs na NVD: ${err.message}`);
    return [];
  }

  const items = (data.vulnerabilities || []).map(({ cve }) => {
    const metric =
      cve.metrics?.cvssMetricV31?.[0] ||
      cve.metrics?.cvssMetricV30?.[0] ||
      cve.metrics?.cvssMetricV2?.[0];
    const severity = (metric?.baseSeverity || metric?.cvssData?.baseSeverity || "NONE").toUpperCase();
    const summary = (cve.descriptions.find((d) => d.lang === "en") || {}).value || "";
    return {
      id: cve.id,
      published: cve.published,
      severity,
      score: metric ? metric.cvssData.baseScore : null,
      color: SEVERITY_COLORS[severity] || SEVERITY_COLORS.NONE,
      summary: summary.length > 160 ? `${summary.slice(0, 157)}...` : summary,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    };
  });

  // Prioriza CVEs ja avaliados (com nota CVSS), preenchendo o restante
  // com os mais recentes ainda sem nota.
  const scored = items
    .filter((c) => c.score !== null)
    .sort((a, b) => new Date(b.published) - new Date(a.published));
  const unscored = items
    .filter((c) => c.score === null)
    .sort((a, b) => new Date(b.published) - new Date(a.published));

  return [...scored, ...unscored].slice(0, limit);
}

async function main() {
  console.log("Buscando top portas...");
  const topPortsRaw = await fetchJSON(
    `https://isc.sans.edu/api/topports/records/${TOP_PORTS_LIMIT}?json`
  );
  // A API retorna um objeto com chaves numericas ("0","1",...) mais "date"/"limit",
  // nao um array puro.
  const topPortsRawList = Object.values(topPortsRaw).filter(
    (v) => v && typeof v === "object" && "targetport" in v
  );
  const topPorts = topPortsRawList.map((p) => ({
    port: Number(p.targetport),
    records: Number(p.records),
    targets: Number(p.targets),
    sources: Number(p.sources),
  }));

  await sleep(REQUEST_DELAY_MS);

  console.log("Buscando top IPs de origem...");
  const topIps = await fetchJSON(
    `https://isc.sans.edu/api/topips/records/${TOP_IPS_LIMIT}?json`
  );

  const centroids = await loadCentroids();

  const events = [];
  let ipIndex = 0;
  for (const entry of topIps) {
    const ip = (entry.source || entry.ip || "").trim();
    if (!ip) continue;

    await sleep(REQUEST_DELAY_MS);
    let country = null;
    try {
      const details = await fetchJSON(`https://isc.sans.edu/api/ip/${ip}?json`);
      country = details?.ip?.ascountry || null;
    } catch (err) {
      console.warn(`Nao foi possivel resolver pais de ${ip}: ${err.message}`);
      continue;
    }

    const centroid = country ? centroids[country] : null;
    if (!centroid) {
      console.warn(`Sem centroide para pais "${country}" (ip ${ip}), pulando.`);
      continue;
    }

    const hub = TARGET_HUBS[ipIndex % TARGET_HUBS.length];
    const port = topPorts.length ? pickWeightedPort(topPorts) : null;
    const { label: attackType, category } = port
      ? describePort(port)
      : { label: "Atividade suspeita", category: "other" };

    events.push({
      id: `${ip}-${Date.now()}-${ipIndex}`,
      ip,
      country,
      sourceCoord: jitterAround(centroid, 3),
      targetCoord: jitterAround(hub.coord, 3),
      targetHub: hub.name,
      targetCountry: hub.country,
      reports: Number(entry.reports) || 0,
      targets: Number(entry.targets) || 0,
      port,
      attackType,
      category,
      color: CATEGORY_COLORS[category] || CATEGORY_COLORS.other,
    });
    ipIndex++;
  }

  await sleep(REQUEST_DELAY_MS);
  console.log("Buscando CVEs recentes na NVD...");
  const cves = await fetchRecentCVEs(CVE_LIMIT);

  // Ranking dos paises "mais atacados" com base no volume (reports) dos
  // eventos coletados, agrupado pelo pais do hub de destino de cada evento.
  // Como os hubs de destino sao estilizados (ver nota acima), este ranking
  // fica limitado aos paises representados pelos hubs -- nao e uma medicao
  // real de vitimas por pais.
  const countryTotals = new Map();
  for (const ev of events) {
    const key = ev.targetCountry;
    if (!key) continue;
    countryTotals.set(key, (countryTotals.get(key) || 0) + ev.reports);
  }
  const countryRanking = [...countryTotals.entries()]
    .map(([country, reports]) => ({ country, reports }))
    .sort((a, b) => b.reports - a.reports);

  const payload = {
    generatedAt: new Date().toISOString(),
    source: "SANS Internet Storm Center / DShield (isc.sans.edu)",
    portAttributionNote:
      "A porta/tipo de ataque de cada evento e sorteada com peso pela distribuicao agregada de topports do dia; a API nao associa porta a um IP atacante especifico.",
    cveNote:
      "Lista informativa de CVEs publicados recentemente (fonte: NVD/NIST), sem relacao direta com os eventos de ataque exibidos no mapa.",
    countryRankingNote:
      "Ranking baseado no volume de registros dos eventos coletados, agrupado pelo pais dos hubs de destino estilizados -- nao reflete vitimas reais por pais.",
    ports: topPorts,
    events,
    cves,
    countryRanking,
    categories: CATEGORY_ORDER.map((key) => ({
      key,
      label: CATEGORY_LABELS[key],
      color: CATEGORY_COLORS[key],
    })),
  };

  await writeFile(
    join(DATA_DIR, "attacks.json"),
    JSON.stringify(payload, null, 2)
  );
  console.log(`OK: ${events.length} eventos, ${payload.ports.length} portas, ${cves.length} CVEs -> data/attacks.json`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
