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
import { buildThreatTags } from "./threat-feeds.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, "..", "data");

const CONTACT = process.env.DSHIELD_CONTACT || "github.com/SEU_USUARIO/SEU_REPO";
const USER_AGENT = `cybermap-clone (+${CONTACT})`;

const TOP_IPS_LIMIT = Number(process.env.TOP_IPS_LIMIT || 100);
// So os primeiros IPs passam pelo api/ip do DShield (1 requisicao cada, serve
// pras tags de threat feed). O restante tem so o pais resolvido em lote.
const IP_DETAIL_LIMIT = Number(process.env.IP_DETAIL_LIMIT || 20);
const TOP_PORTS_LIMIT = Number(process.env.TOP_PORTS_LIMIT || 10);
const TOTAL_PORTS_SAMPLE = Number(process.env.TOTAL_PORTS_SAMPLE || 50);
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
  // Americas
  { name: "US-Washington", coord: [-77.03, 38.9], country: "US" },
  { name: "US-SanFrancisco", coord: [-122.42, 37.77], country: "US" },
  { name: "CA-Toronto", coord: [-79.38, 43.65], country: "CA" },
  { name: "MX-MexicoCity", coord: [-99.13, 19.43], country: "MX" },
  { name: "BR-SaoPaulo", coord: [-46.63, -23.55], country: "BR" },
  { name: "AR-BuenosAires", coord: [-58.38, -34.6], country: "AR" },
  { name: "CL-Santiago", coord: [-70.67, -33.45], country: "CL" },
  { name: "CO-Bogota", coord: [-74.07, 4.71], country: "CO" },
  { name: "PE-Lima", coord: [-77.04, -12.05], country: "PE" },
  // Europa
  { name: "GB-London", coord: [-0.13, 51.51], country: "GB" },
  { name: "IE-Dublin", coord: [-6.26, 53.35], country: "IE" },
  { name: "FR-Paris", coord: [2.35, 48.86], country: "FR" },
  { name: "DE-Frankfurt", coord: [8.68, 50.11], country: "DE" },
  { name: "NL-Amsterdam", coord: [4.9, 52.37], country: "NL" },
  { name: "ES-Madrid", coord: [-3.7, 40.42], country: "ES" },
  { name: "PT-Lisbon", coord: [-9.14, 38.72], country: "PT" },
  { name: "IT-Milan", coord: [9.19, 45.46], country: "IT" },
  { name: "CH-Zurich", coord: [8.54, 47.38], country: "CH" },
  { name: "SE-Stockholm", coord: [18.07, 59.33], country: "SE" },
  { name: "PL-Warsaw", coord: [21.01, 52.23], country: "PL" },
  { name: "UA-Kyiv", coord: [30.52, 50.45], country: "UA" },
  { name: "TR-Istanbul", coord: [28.98, 41.01], country: "TR" },
  // Oriente Medio e Africa
  { name: "IL-TelAviv", coord: [34.78, 32.09], country: "IL" },
  { name: "SA-Riyadh", coord: [46.68, 24.71], country: "SA" },
  { name: "AE-Dubai", coord: [55.27, 25.2], country: "AE" },
  { name: "EG-Cairo", coord: [31.24, 30.04], country: "EG" },
  { name: "NG-Lagos", coord: [3.38, 6.52], country: "NG" },
  { name: "KE-Nairobi", coord: [36.82, -1.29], country: "KE" },
  { name: "ZA-Johannesburg", coord: [28.05, -26.2], country: "ZA" },
  // Asia-Pacifico
  { name: "IN-Mumbai", coord: [72.88, 19.08], country: "IN" },
  { name: "CN-Shanghai", coord: [121.47, 31.23], country: "CN" },
  { name: "HK-HongKong", coord: [114.17, 22.32], country: "HK" },
  { name: "JP-Tokyo", coord: [139.69, 35.68], country: "JP" },
  { name: "KR-Seoul", coord: [126.98, 37.57], country: "KR" },
  { name: "SG-Singapore", coord: [103.82, 1.35], country: "SG" },
  { name: "MY-KualaLumpur", coord: [101.69, 3.14], country: "MY" },
  { name: "TH-Bangkok", coord: [100.5, 13.76], country: "TH" },
  { name: "VN-HoChiMinh", coord: [106.66, 10.82], country: "VN" },
  { name: "PH-Manila", coord: [120.98, 14.6], country: "PH" },
  { name: "ID-Jakarta", coord: [106.85, -6.21], country: "ID" },
  { name: "AU-Sydney", coord: [151.21, -33.87], country: "AU" },
  { name: "NZ-Auckland", coord: [174.76, -36.85], country: "NZ" },
];

// Paises grandes: o centroide sozinho concentraria todos os IPs num ponto so
// (e muitas vezes no meio do nada), entao a origem e espalhada numa area maior.
const LARGE_COUNTRY_SPREAD = {
  US: 20, CN: 20, RU: 30, BR: 18, CA: 24, AU: 18, IN: 12, AR: 12, KZ: 18, MX: 10,
};
const DEFAULT_SOURCE_SPREAD = 5;

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

// blocklist.de publica listas de IPs reportados por atacar cada servico
// (ssh, mail...). Diferente do DShield, aqui o tipo de ataque e real por IP:
// ele esta na lista daquele servico. Pegamos so uma amostra aleatoria de cada
// lista, porque elas tem milhares de IPs e o objetivo e dar variedade de
// paises de origem, nao espelhar a lista inteira.
const BLOCKLIST_SAMPLE_PER_LIST = Number(process.env.BLOCKLIST_SAMPLE_PER_LIST || 15);
const BLOCKLIST_SERVICES = [
  { key: "ssh", label: "SSH Brute-force", category: "remote" },
  { key: "ftp", label: "FTP Brute-force", category: "remote" },
  { key: "mail", label: "Abuso de e-mail / Spam", category: "mail" },
  { key: "apache", label: "Ataque a servidor web", category: "web" },
  { key: "sip", label: "SIP/VoIP Scan", category: "net" },
  { key: "bots", label: "Botnet", category: "other" },
];

function shuffled(list) {
  const copy = [...list];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

// Devolve [{ ip, service }] sem repetir IP (nem os ja usados em `skipIps`).
// Qualquer falha de rede vira aviso: a coleta segue so com o DShield.
async function fetchBlocklistSample(skipIps) {
  const seen = new Set(skipIps);
  const sample = [];
  for (const service of BLOCKLIST_SERVICES) {
    try {
      const res = await fetch(`https://lists.blocklist.de/lists/${service.key}.txt`, {
        headers: { "User-Agent": USER_AGENT },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const ips = (await res.text())
        .split(/\s+/)
        .filter((s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && !seen.has(s));
      for (const ip of shuffled(ips).slice(0, BLOCKLIST_SAMPLE_PER_LIST)) {
        seen.add(ip);
        sample.push({ ip, service });
      }
    } catch (err) {
      console.warn(`Nao foi possivel ler a lista ${service.key} do blocklist.de: ${err.message}`);
    }
    await sleep(REQUEST_DELAY_MS);
  }
  return sample;
}

// Resolve o pais de varios IPs de uma vez via country.is (geo-IP gratuito,
// ate 100 IPs por chamada). Falha de rede nao derruba a coleta: devolve um
// Map vazio e o chamador cai no pais informado pelo DShield.
async function lookupCountriesBulk(ips) {
  const result = new Map();
  for (let i = 0; i < ips.length; i += 100) {
    const chunk = ips.slice(i, i + 100);
    try {
      const res = await fetch("https://api.country.is", {
        method: "POST",
        headers: { "User-Agent": USER_AGENT, "Content-Type": "application/json" },
        body: JSON.stringify(chunk),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const list = await res.json();
      for (const item of Array.isArray(list) ? list : []) {
        if (item?.ip && item?.country) result.set(item.ip, item.country);
      }
    } catch (err) {
      console.warn(`Geo-IP em lote falhou (${err.message}); usando so o pais do DShield.`);
    }
  }
  return result;
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

// A API retorna um objeto com chaves numericas ("0","1",...) mais "date"/"limit",
// nao um array puro. dateStr (YYYY-MM-DD) e opcional -- omitido, a API usa hoje.
async function fetchTopPorts(limit, dateStr) {
  const suffix = dateStr ? `/${dateStr}` : "";
  const raw = await fetchJSON(`https://isc.sans.edu/api/topports/records/${limit}${suffix}?json`);
  const list = Object.values(raw).filter((v) => v && typeof v === "object" && "targetport" in v);
  const ports = list.map((p) => ({
    port: Number(p.targetport),
    records: Number(p.records),
    targets: Number(p.targets),
    sources: Number(p.sources),
  }));
  const date = typeof raw.date === "string" ? raw.date : dateStr || null;
  return { ports, date };
}

function isoDateDaysAgo(days) {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

async function main() {
  console.log("Buscando top portas (hoje)...");
  const { ports: topPorts, date: portsDate } = await fetchTopPorts(TOP_PORTS_LIMIT);

  await sleep(REQUEST_DELAY_MS);

  console.log("Buscando top portas (7 dias atras)...");
  let portsWeekAgo = [];
  let portsWeekAgoDate = null;
  try {
    const weekAgo = await fetchTopPorts(TOP_PORTS_LIMIT, isoDateDaysAgo(7));
    portsWeekAgo = weekAgo.ports;
    portsWeekAgoDate = weekAgo.date;
  } catch (err) {
    console.warn(`Nao foi possivel buscar portas de 7 dias atras: ${err.message}`);
  }

  await sleep(REQUEST_DELAY_MS);

  // Amostra maior (so pra somar), sem inflar a lista exibida na tela --
  // da um numero mais representativo do volume total do dia sem custar
  // requisicoes extras de TCP/UDP para portas que nao aparecem na lista.
  console.log("Buscando amostra ampla de portas para o total do dia...");
  let totalRecordsToday = null;
  try {
    const { ports: totalList } = await fetchTopPorts(TOTAL_PORTS_SAMPLE);
    totalRecordsToday = totalList.reduce((sum, p) => sum + (Number(p.records) || 0), 0);
  } catch (err) {
    console.warn(`Nao foi possivel calcular o total do dia: ${err.message}`);
  }

  console.log("Buscando proporcao TCP/UDP por porta...");
  for (const p of topPorts) {
    await sleep(REQUEST_DELAY_MS);
    try {
      const detail = await fetchJSON(`https://isc.sans.edu/api/port/${p.port}?json`);
      const tcp = Number(detail?.data?.tcp);
      const udp = Number(detail?.data?.udp);
      if (!Number.isNaN(tcp)) p.tcpPct = tcp;
      if (!Number.isNaN(udp)) p.udpPct = udp;
    } catch (err) {
      console.warn(`Nao foi possivel obter proporcao TCP/UDP da porta ${p.port}: ${err.message}`);
    }
  }

  await sleep(REQUEST_DELAY_MS);

  console.log("Buscando top IPs de origem...");
  const topIps = await fetchJSON(
    `https://isc.sans.edu/api/topips/records/${TOP_IPS_LIMIT}?json`
  );

  const centroids = await loadCentroids();

  const entries = topIps.filter((e) => (e.source || e.ip || "").trim());
  const dshieldIps = entries.map((e) => (e.source || e.ip).trim());

  console.log("Buscando amostra de IPs no blocklist.de...");
  const blocklistSample = await fetchBlocklistSample(dshieldIps);

  console.log(`Resolvendo pais de ${dshieldIps.length + blocklistSample.length} IPs em lote (geo-IP)...`);
  const geoCountries = await lookupCountriesBulk([...dshieldIps, ...blocklistSample.map((b) => b.ip)]);

  const events = [];
  let ipIndex = 0;
  for (const [position, entry] of entries.entries()) {
    const ip = (entry.source || entry.ip).trim();

    // Pais do DShield (ASN) so e buscado para os primeiros IPs, que tambem
    // ganham tags de threat feed. Quando existe, o geo-IP tem preferencia
    // porque reflete onde o IP esta de fato, nao onde o ASN foi registrado.
    let asnCountry = null;
    let threatTags = [];
    if (position < IP_DETAIL_LIMIT) {
      await sleep(REQUEST_DELAY_MS);
      try {
        const details = await fetchJSON(`https://isc.sans.edu/api/ip/${ip}?json`);
        asnCountry = details?.ip?.ascountry || null;
        threatTags = buildThreatTags(details?.ip?.threatfeeds);
      } catch (err) {
        console.warn(`Nao foi possivel consultar ${ip} no DShield: ${err.message}`);
      }
    }
    const country = geoCountries.get(ip) || asnCountry;

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
      sourceCoord: jitterAround(centroid, LARGE_COUNTRY_SPREAD[country] || DEFAULT_SOURCE_SPREAD),
      targetCoord: jitterAround(hub.coord, 3),
      targetHub: hub.name,
      targetCountry: hub.country,
      reports: Number(entry.reports) || 0,
      targets: Number(entry.targets) || 0,
      port,
      attackType,
      category,
      color: CATEGORY_COLORS[category] || CATEGORY_COLORS.other,
      threatTags,
      origin: "dshield",
    });
    ipIndex++;
  }

  for (const { ip, service } of blocklistSample) {
    const country = geoCountries.get(ip);
    const centroid = country ? centroids[country] : null;
    if (!centroid) continue;

    const hub = TARGET_HUBS[ipIndex % TARGET_HUBS.length];
    events.push({
      id: `${ip}-${Date.now()}-${ipIndex}`,
      ip,
      country,
      sourceCoord: jitterAround(centroid, LARGE_COUNTRY_SPREAD[country] || DEFAULT_SOURCE_SPREAD),
      targetCoord: jitterAround(hub.coord, 3),
      targetHub: hub.name,
      targetCountry: hub.country,
      // Sem contagem de registros nem porta: a lista so informa que o IP
      // foi reportado atacando aquele servico.
      reports: null,
      targets: null,
      port: null,
      attackType: service.label,
      category: service.category,
      color: CATEGORY_COLORS[service.category] || CATEGORY_COLORS.other,
      threatTags: [
        { key: `blocklistde_${service.key}`, label: `Blocklist.de — ${service.label}`, lastSeen: null },
      ],
      origin: "blocklist.de",
    });
    ipIndex++;
  }

  await sleep(REQUEST_DELAY_MS);
  console.log("Buscando CVEs recentes na NVD...");
  const cves = await fetchRecentCVEs(CVE_LIMIT);

  // Ranking dos paises "mais atacados" com base no volume (reports) dos
  // eventos coletados, agrupado pelo pais do hub de destino de cada evento.
  // Eventos do blocklist.de nao tem `reports`, entao nao entram na soma.
  // Como os hubs de destino sao estilizados (ver nota acima), este ranking
  // fica limitado aos paises representados pelos hubs -- nao e uma medicao
  // real de vitimas por pais.
  const countryTotals = new Map();
  for (const ev of events) {
    const key = ev.targetCountry;
    if (!key) continue;
    countryTotals.set(key, (countryTotals.get(key) || 0) + (ev.reports || 0));
  }
  const countryRanking = [...countryTotals.entries()]
    .map(([country, reports]) => ({ country, reports }))
    .sort((a, b) => b.reports - a.reports);

  const payload = {
    generatedAt: new Date().toISOString(),
    source: "SANS Internet Storm Center / DShield (isc.sans.edu)",
    portAttributionNote:
      "A porta/tipo de ataque de cada evento e sorteada com peso pela distribuicao agregada de topports do dia; a API nao associa porta a um IP atacante especifico.",
    threatTagsNote:
      "As tags de ameaca (quando presentes) vem do campo threatfeeds da API do DShield -- sao listas de reputacao de terceiros que ja flagraram aquele IP especifico. E dado real, nao inferido; a maioria dos IPs nao tem nenhuma tag.",
    portProtocolNote:
      "tcpPct/udpPct vem do campo tcp/udp de api/port/{porta} do DShield. Nao somam exatamente 100 (parte do trafego fica sem protocolo classificado); nao sao uma contagem de registros, sao a proporcao reportada pela API.",
    totalRecordsToday,
    portsDate,
    totalRecordsNote:
      `Soma dos registros (records) das ${TOTAL_PORTS_SAMPLE} portas mais reportadas no dia pela API topports do DShield. Nao e o total absoluto de todos os ataques da internet -- e uma amostra real considerável, nao uma estimativa inventada.`,
    cveNote:
      "Lista informativa de CVEs publicados recentemente (fonte: NVD/NIST), sem relacao direta com os eventos de ataque exibidos no mapa.",
    countryRankingNote:
      "Ranking baseado no volume de registros dos eventos coletados, agrupado pelo pais dos hubs de destino estilizados -- nao reflete vitimas reais por pais.",
    ports: topPorts,
    portsHistory: {
      today: { date: portsDate, ports: topPorts },
      week_ago: { date: portsWeekAgoDate, ports: portsWeekAgo },
    },
    hubsNote:
      "Hubs de destino ilustrativos: a API do DShield nao expoe a localizacao real dos sensores. Cada disparo no mapa sorteia um destino entre estes.",
    sourceCountryNote:
      "Pais de origem via geo-IP (country.is) quando disponivel, senao o pais do ASN informado pelo DShield. A posicao exata dentro do pais e sorteada ao redor do centroide.",
    blocklistNote:
      "Parte dos IPs de origem vem de uma amostra aleatoria das listas por servico do blocklist.de (ssh, mail, apache, ftp, sip, bots). Nesses eventos o tipo de ataque e real (o IP foi reportado atacando aquele servico), mas nao ha contagem de registros nem porta; sao marcados com origin=blocklist.de.",
    hubs: TARGET_HUBS,
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
