// Ranking real de paises-alvo de ataques DDoS (camada 7) via Cloudflare Radar.
// Exige um token de API com permissao Account > Radar > Read, lido de
// CLOUDFLARE_API_TOKEN. Sem token (ou com qualquer falha) devolve null e o
// restante da coleta segue normalmente.
//
// Atencao ao que o dado e: o pais e o de COBRANCA da zona atacada, medido sobre
// o trafego que passa pela Cloudflare (DDoS mitigado). Nao e o mesmo universo
// do DShield (varreduras contra honeypots) e nao e geografia de servidores.

const RADAR_URL =
  "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target";

// Converte a resposta da API em { items, meta }. Separado do fetch para poder
// ser testado offline com uma resposta de exemplo.
export function parseTargetRanking(json) {
  const rows = json?.result?.top_0;
  if (!json?.success || !Array.isArray(rows)) return null;

  const items = rows
    .map((row) => ({
      country: String(row.targetCountryAlpha2 || "").toUpperCase(),
      name: row.targetCountryName || null,
      share: Number(row.value),
    }))
    .filter((item) => /^[A-Z]{2}$/.test(item.country) && Number.isFinite(item.share) && item.share > 0)
    .sort((a, b) => b.share - a.share);
  if (!items.length) return null;

  const range = json.result?.meta?.dateRange?.[0] || {};
  return {
    items,
    meta: {
      start: range.startTime || null,
      end: range.endTime || null,
      lastUpdated: json.result?.meta?.lastUpdated || null,
    },
  };
}

export async function fetchTargetRanking({ token, limit = 30, userAgent }) {
  if (!token) {
    console.log("CLOUDFLARE_API_TOKEN ausente: ranking de paises-alvo fica ilustrativo.");
    return null;
  }
  try {
    const res = await fetch(`${RADAR_URL}?dateRange=1d&limit=${limit}&format=json`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        "User-Agent": userAgent,
      },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const parsed = parseTargetRanking(await res.json());
    if (!parsed) throw new Error("resposta sem a lista esperada");
    return parsed;
  } catch (err) {
    console.warn(`Nao foi possivel obter o ranking do Cloudflare Radar: ${err.message}`);
    return null;
  }
}
