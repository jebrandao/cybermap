(function () {
  const svg = d3.select("#map");
  const tooltip = d3.select("#tooltip");
  const updatedAtEl = document.getElementById("updated-at");
  const eventListEl = document.getElementById("event-list");
  const portListEl = document.getElementById("port-list");
  const cveListEl = document.getElementById("cve-list");
  const legendEl = document.getElementById("map-legend");
  const countryRankingEl = document.getElementById("country-ranking");

  let countryNames = {};
  function countryName(code) {
    if (!code) return "?";
    return countryNames[code] || code;
  }

  // Estado da visualizacao 3D (globe.gl), carregada e inicializada so
  // quando o usuario troca pra 3D pela primeira vez.
  let viewMode = "2d";
  let worldFeatures = null;
  let liveData = null;
  let globeInstance = null;
  let globeLibsLoaded = false;
  let globeArcs = [];
  let globeRings = [];

  // Tempo que os pontos de origem (azuis) e de impacto (vermelhos) levam
  // para esmaecer ate sumir depois de acesos.
  const FADE_MS = 5000;
  const SOURCE_COLOR = "#33e0ff";
  const IMPACT_COLOR = "#ff2d2d";

  const WIDTH = 960;
  const HEIGHT = 520;
  svg.attr("viewBox", `0 0 ${WIDTH} ${HEIGHT}`);

  const projection = d3.geoNaturalEarth1().fitSize([WIDTH, HEIGHT], { type: "Sphere" });
  const path = d3.geoPath(projection);

  const landLayer = svg.append("g").attr("class", "land-layer");
  const arcLayer = svg.append("g").attr("class", "arc-layer");
  const dotLayer = svg.append("g").attr("class", "dot-layer");

  function arcPath(sourceCoord, targetCoord) {
    const [x1, y1] = projection(sourceCoord);
    const [x2, y2] = projection(targetCoord);
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2 - Math.min(120, Math.hypot(x2 - x1, y2 - y1) * 0.35);
    return `M${x1},${y1} Q${mx},${my} ${x2},${y2}`;
  }

  function flagSpan(countryCode) {
    if (!countryCode) return '<span class="flag flag-empty"></span>';
    return `<span class="flag fi fi-${countryCode.toLowerCase()}" title="${countryCode}"></span>`;
  }

  function showTooltip(html, [x, y]) {
    tooltip
      .html(html)
      .style("left", `${x}px`)
      .style("top", `${y}px`)
      .classed("hidden", false);
  }
  function hideTooltip() {
    tooltip.classed("hidden", true);
  }

  function impactPulse(coord, color) {
    const [x, y] = projection(coord);
    dotLayer
      .append("circle")
      .attr("class", "pulse")
      .attr("cx", x)
      .attr("cy", y)
      .attr("r", 2)
      .attr("fill", color)
      .transition()
      .duration(150)
      .attr("opacity", 0.9)
      .transition()
      .duration(700)
      .attr("r", 16)
      .attr("opacity", 0)
      .remove();
  }

  // Sorteia um hub de destino a cada disparo (evitando o proprio pais da
  // origem, pra o arco sempre atravessar o mapa). Sem isso cada IP atacaria
  // sempre o mesmo hub e 19 eventos virariam 19 rotas fixas se repetindo.
  // Os hubs ja sao ilustrativos, entao isso nao altera nenhum dado real.
  function withRandomDestination(ev) {
    if (!hubList.length) return ev;
    const candidates = hubList.filter((h) => h.country !== ev.country);
    const pool = candidates.length ? candidates : hubList;
    const hub = pool[Math.floor(Math.random() * pool.length)];
    return {
      ...ev,
      targetHub: hub.name,
      targetCountry: hub.country,
      targetCoord: [
        hub.coord[0] + (Math.random() - 0.5) * 3,
        hub.coord[1] + (Math.random() - 0.5) * 3,
      ],
    };
  }

  // Ponto de entrada unico chamado pelo loop de animacao: atualiza os
  // paineis (sempre) e delega o efeito visual no mapa para o modo ativo.
  function fireEvent(baseEvent) {
    const ev = withRandomDestination(baseEvent);
    prependEventToList(ev);
    bumpCountryRanking(ev.targetCountry);
    if (viewMode === "3d") {
      fire3D(ev);
    } else {
      fire2D(ev);
    }
  }

  // Desenha o caminho do ataque: a linha "revela" do zero ate o comprimento
  // total (dash-offset) enquanto um ponto percorre o mesmo trajeto, saindo
  // da origem e chegando ao destino, como no cybermap da Kaspersky.
  function fire2D(ev) {
    const color = ev.color || "#33e0ff";
    const d = arcPath(ev.sourceCoord, ev.targetCoord);

    const arc = arcLayer
      .append("path")
      .attr("class", "arc")
      .attr("d", d)
      .attr("stroke", color)
      .attr("opacity", 0.9);

    const totalLength = arc.node().getTotalLength();
    arc
      .attr("stroke-dasharray", `${totalLength} ${totalLength}`)
      .attr("stroke-dashoffset", totalLength)
      .transition()
      .duration(1100)
      .ease(d3.easeCubicOut)
      .attr("stroke-dashoffset", 0)
      .transition()
      .duration(500)
      .attr("opacity", 0)
      .remove();

    const travelDot = dotLayer
      .append("circle")
      .attr("class", "travel-dot")
      .attr("r", 2.6)
      .attr("fill", color);

    travelDot
      .transition()
      .duration(1100)
      .ease(d3.easeCubicOut)
      .attrTween("transform", () => (t) => {
        const p = arc.node().getPointAtLength(t * totalLength);
        return `translate(${p.x},${p.y})`;
      })
      .on("end", () => {
        impactPulse(ev.targetCoord, color);
        lightImpactDot(ev);
        travelDot.remove();
      });

    impactPulse(ev.sourceCoord, color);
    lightSourceDot(ev);
  }

  // Incremento proporcional ao valor atual (0.5%-2%, minimo 1) em vez de
  // sempre +1 -- com os valores iniciais agora na casa dos milhares, um +1
  // fixo seria imperceptivel.
  function bumpCountryRanking(country) {
    if (!country) return;
    const current = countryTotals.get(country) || 0;
    const bump = Math.max(1, Math.round(current * (0.005 + Math.random() * 0.015)));
    countryTotals.set(country, current + bump);
    renderCountryRanking(countryRankingArray(), country);
  }

  // As tags (quando existem) vem do campo threatfeeds do DShield: listas de
  // reputacao de terceiros que ja flagraram aquele IP -- dado real, nao
  // inferido. A maioria dos IPs nao tem nenhuma.
  function threatTagsHtml(tags) {
    if (!tags || !tags.length) return "";
    return `<div class="threat-tags">${tags
      .map((t) => {
        const title = t.lastSeen ? ` title="Visto pela ultima vez em ${t.lastSeen}"` : "";
        return `<span class="threat-tag"${title}>${t.label}</span>`;
      })
      .join("")}</div>`;
  }

  // Eventos vindos do blocklist.de nao trazem contagem de registros.
  function reportsHtml(ev) {
    return ev.reports ? `<br/>${ev.reports.toLocaleString("pt-BR")} registros` : "";
  }

  function prependEventToList(ev) {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="event-row">
        <div class="attack-line">
          ${flagSpan(ev.country)}
          <span class="attack-type" style="color:${ev.color || "#33e0ff"}">${ev.attackType || "Atividade suspeita"}</span>
          ${flagSpan(ev.targetCountry)}
        </div>
        <span class="event-meta"><span class="country">${countryName(ev.country)}</span> &middot; ${ev.ip}</span>
        ${threatTagsHtml(ev.threatTags)}
      </div>`;
    eventListEl.prepend(li);
    while (eventListEl.children.length > 14) {
      eventListEl.removeChild(eventListEl.lastChild);
    }
  }

  // tcpPct/udpPct vem de api/port/{porta} do DShield -- proporcao real do
  // trafego daquela porta, nao uma contagem (por isso nao somam sempre 100).
  function protocolSplitHtml(p) {
    const tcp = p.tcpPct;
    const udp = p.udpPct;
    if (tcp === undefined || udp === undefined) return "";
    const tcpW = Math.max(0, Math.min(100, tcp));
    const udpW = Math.max(0, Math.min(100, udp));
    return `
      <div class="proto-split" title="TCP ${tcp}% · UDP ${udp}%">
        <div class="proto-bar">
          <span class="proto-tcp" style="width:${tcpW}%"></span>
          <span class="proto-udp" style="width:${udpW}%"></span>
        </div>
        <span class="proto-label">TCP ${tcp}% · UDP ${udp}%</span>
      </div>`;
  }

  function renderAttackCounter(total) {
    if (total === null || total === undefined) return;
    const el = document.getElementById("attack-counter");
    document.getElementById("attack-counter-value").textContent = total.toLocaleString("pt-BR");
    el.classList.remove("hidden");
  }

  function renderUpdateTime(generatedAt) {
    if (!generatedAt) return;
    const date = new Date(generatedAt);
    if (Number.isNaN(date.getTime())) return;
    const el = document.getElementById("update-time");
    el.textContent = `Atualizado às ${date.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}`;
    el.classList.remove("hidden");
    positionUpdateTime();
  }

  // Fica ao lado da legenda, na mesma altura, quando ha espaco; sobe pra
  // cima dela (fica empilhado) quando a largura da tela nao da pra caber
  // os dois lado a lado sem sobrepor.
  function positionUpdateTime() {
    const el = document.getElementById("update-time");
    const items = document.querySelectorAll("#map-legend li");
    if (el.classList.contains("hidden") || !items.length) return;
    el.classList.remove("stacked");
    const elBox = el.getBoundingClientRect();
    // Compara com o item mais a direita de fato (o <ul> em si ocupa 100% da
    // largura por causa do left:0/right:0, mesmo com o conteudo centralizado).
    const rightmost = [...items].reduce(
      (max, li) => Math.max(max, li.getBoundingClientRect().right),
      0
    );
    const lastItemBox = items[items.length - 1].getBoundingClientRect();
    const overlapsVertically = elBox.bottom > lastItemBox.top;
    const overlapsHorizontally = elBox.left < rightmost + 12;
    if (overlapsVertically && overlapsHorizontally) {
      el.classList.add("stacked");
    }
  }

  window.addEventListener("resize", () => positionUpdateTime());

  let portsHistory = null;

  function initPortsPeriodToggle() {
    document.querySelectorAll(".period-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (!portsHistory) return;
        document.querySelectorAll(".period-btn").forEach((b) => b.classList.toggle("active", b === btn));
        const snapshot = portsHistory[btn.dataset.period];
        renderPortList((snapshot && snapshot.ports) || []);
      });
    });
  }

  function renderPortList(ports) {
    portListEl.innerHTML = "";
    ports
      .slice()
      .sort((a, b) => b.records - a.records)
      .slice(0, 8)
      .forEach((p) => {
        const li = document.createElement("li");
        li.innerHTML = `
          <div class="port-row">
            <span>porta ${p.port}</span><span class="count">${p.records.toLocaleString("pt-BR")}</span>
          </div>
          ${protocolSplitHtml(p)}`;
        portListEl.appendChild(li);
      });
  }

  // Tally ao vivo: quantas vezes cada pais-alvo apareceu nos ataques
  // exibidos em "Eventos recentes" desde que a pagina foi carregada.
  let countryTotals = new Map();

  // Comeca com valores aleatorios (em vez da contagem literal, quase empatada)
  // para que o ranking ja nasca embaralhado e as posicoes tenham de onde variar.
  // Os paises dos hubs de destino ilustrativos sao uma fatia pequena perto dos
  // 200+ paises do mundo real -- a soma deles nao deveria bater no contador
  // principal (isso exigiria numeros irreais por pais). Em vez disso, mira
  // numa fracao plausivel do total (os paises mais atacados concentrando uma parcela
  // desproporcional do volume, como costuma acontecer na pratica), com
  // pesos aleatorios e desiguais entre os paises em vez de uma faixa fixa
  // desconectada do contador.
  const COUNTRY_SHARE_OF_TOTAL = 0.12;

  function buildInitialCountryTally(hubs, totalRecordsToday) {
    const countries = [...new Set(hubs.map((h) => h.country).filter(Boolean))];
    const map = new Map();
    if (!countries.length) return map;

    const targetSum = (totalRecordsToday || 0) * COUNTRY_SHARE_OF_TOTAL;
    if (!targetSum) {
      // Sem contador disponivel: mantem numeros pequenos e embaralhados.
      countries.forEach((c) => map.set(c, 5 + Math.floor(Math.random() * 40)));
      return map;
    }

    // Pesos com variancia realista (alguns paises concentram bem mais que
    // outros) em vez de distribuir o total igualmente entre todos.
    const weights = countries.map(() => Math.pow(Math.random(), 2) + 0.05);
    const weightSum = weights.reduce((a, b) => a + b, 0);
    countries.forEach((country, i) => {
      const share = Math.round((weights[i] / weightSum) * targetSum);
      map.set(country, Math.max(1, share));
    });
    return map;
  }

  function countryRankingArray() {
    return [...countryTotals.entries()]
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count);
  }

  function renderCountryRanking(ranking, bumpedCountry) {
    countryRankingEl.innerHTML = "";
    if (!ranking.length) {
      countryRankingEl.innerHTML = '<li class="event-meta">sem dados</li>';
      return;
    }
    ranking.forEach((r) => {
      const li = document.createElement("li");
      if (r.country === bumpedCountry) li.classList.add("rank-bump");
      li.innerHTML = `
        <span class="rank-flag">${flagSpan(r.country)}<span class="rank-country">${countryName(r.country)}</span></span>
        <span class="count">${r.count.toLocaleString("pt-BR")}</span>`;
      countryRankingEl.appendChild(li);
    });
  }

  function renderCveList(cves) {
    cveListEl.innerHTML = "";
    if (!cves.length) {
      cveListEl.innerHTML = '<li class="event-meta">nenhum CVE recente encontrado</li>';
      return;
    }
    cves.forEach((c) => {
      const li = document.createElement("li");
      const dateStr = new Date(c.published).toLocaleDateString("pt-BR");
      li.innerHTML = `
        <div class="cve-row">
          <div class="cve-head">
            <span class="cve-id"><a href="${c.url}" target="_blank" rel="noopener">${c.id}</a></span>
            <span class="cve-severity" style="background:${c.color}22;color:${c.color}">${c.severity}${c.score !== null ? " " + c.score : ""}</span>
          </div>
          <div class="cve-summary">${dateStr} &middot; ${c.summary || "sem descricao"}</div>
        </div>`;
      cveListEl.appendChild(li);
    });
  }

  function renderLegend(categories) {
    legendEl.innerHTML = "";
    categories.forEach((c) => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="legend-swatch" style="background:${c.color}"></span>${c.label}`;
      legendEl.appendChild(li);
    });
  }

  // Fonte unica dos hubs de destino: o primeiro evento visto de cada hub
  // define a posicao do marcador. Os hubs sao ilustrativos, entao o destino
  // de cada disparo e sorteado entre eles em tempo de execucao (ver
  // withRandomDestination) em vez de ficar preso ao hub gravado no JSON.
  let hubList = [];

  function buildHubList(data) {
    // Lista completa gravada pelo script de coleta; o fallback por eventos
    // cobre um attacks.json antigo, sem o campo "hubs".
    if (Array.isArray(data.hubs) && data.hubs.length) return data.hubs;
    const hubs = new Map();
    for (const ev of data.events || []) {
      if (ev.targetHub && !hubs.has(ev.targetHub)) {
        hubs.set(ev.targetHub, { name: ev.targetHub, coord: ev.targetCoord, country: ev.targetCountry });
      }
    }
    return [...hubs.values()];
  }

  function eventTooltipHtml(ev) {
    return (
      `<div class="attack-line">${flagSpan(ev.country)}<strong style="color:${ev.color || "#33e0ff"}">${ev.attackType || "?"}</strong></div>` +
      `${countryName(ev.country)} &middot; ${ev.ip}${reportsHtml(ev)}${threatTagsHtml(ev.threatTags)}`
    );
  }

  // Pontos temporarios: nascem acesos e esmaecem linearmente ate sumir.
  // A origem acende quando o ataque parte; o ponto vermelho aparece no
  // instante em que ele atinge o destino (substitui os hubs fixos).
  function fadingDot(coord, className) {
    const [x, y] = projection(coord);
    return dotLayer
      .append("circle")
      .attr("class", className)
      .attr("cx", x)
      .attr("cy", y)
      .attr("r", 3)
      .attr("opacity", 1)
      .transition()
      .duration(FADE_MS)
      .ease(d3.easeLinear)
      .attr("opacity", 0)
      .remove();
  }

  function lightSourceDot(ev) {
    fadingDot(ev.sourceCoord, "source-dot")
      .selection()
      .on("mousemove", (event) => {
        showTooltip(eventTooltipHtml(ev), [event.offsetX, event.offsetY]);
      })
      .on("mouseleave", hideTooltip);
  }

  function lightImpactDot(ev) {
    fadingDot(ev.targetCoord, "impact-dot")
      .selection()
      .on("mousemove", (event) => {
        showTooltip(countryName(ev.targetCountry), [event.offsetX, event.offsetY]);
      })
      .on("mouseleave", hideTooltip);
  }

  // ---------------------------------------------------------------------
  // Visualizacao 3D (globe.gl / Three.js) -- carregada sob demanda, so
  // quando o usuario troca pra "3D" pela primeira vez, para nao pesar o
  // carregamento inicial de quem nunca usa esse modo.
  // ---------------------------------------------------------------------

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      if (document.querySelector(`script[src="${src}"]`)) return resolve();
      const s = document.createElement("script");
      s.src = src;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error(`Falha ao carregar ${src}`));
      document.head.appendChild(s);
    });
  }

  // O bundle do globe.gl ja embute sua propria copia do Three.js -- carregar
  // um Three.js separado causa conflito de instancias multiplas e quebra a lib.
  async function ensureGlobeLibs() {
    if (globeLibsLoaded) return;
    await loadScript("https://cdn.jsdelivr.net/npm/globe.gl");
    globeLibsLoaded = true;
  }

  // Pontos temporarios do globo (origem azul / impacto vermelho). O globe.gl
  // nao anima opacidade sozinho, entao um timer curto recalcula o alfa de cada
  // ponto a partir da idade e descarta os que ja esmaeceram por completo.
  let globePoints = [];
  let globeFadeTimer = null;

  function hexToRgba(hex, alpha) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha.toFixed(3)})`;
  }

  function fadedPointColor(p) {
    const alpha = Math.max(0, 1 - (Date.now() - p.born) / FADE_MS);
    return hexToRgba(p.baseColor, alpha);
  }

  function addGlobePoint(coord, baseColor, label) {
    globePoints.push({
      lat: coord[1],
      lng: coord[0],
      baseColor,
      radius: 0.9,
      altitude: 0.012,
      label,
      born: Date.now(),
    });
    globeInstance.pointsData([...globePoints]);
  }

  function tickGlobePoints() {
    if (!globeInstance || !globePoints.length) return;
    const now = Date.now();
    globePoints = globePoints.filter((p) => now - p.born < FADE_MS);
    globeInstance.pointsData([...globePoints]);
  }

  function resizeGlobe() {
    if (!globeInstance) return;
    const el = document.getElementById("globe");
    globeInstance.width(el.clientWidth).height(el.clientHeight);
  }

  function initGlobe() {
    const el = document.getElementById("globe");
    globeInstance = new Globe(el)
      .backgroundColor("rgba(0,0,0,0)")
      .showGlobe(true)
      .showAtmosphere(true)
      .atmosphereColor("#33e0ff")
      .atmosphereAltitude(0.18)
      .polygonsData(worldFeatures || [])
      .polygonCapColor(() => "#131a30")
      .polygonSideColor(() => "rgba(35,45,79,0.5)")
      .polygonStrokeColor(() => "#232d4f")
      .polygonAltitude(0.005)
      .polygonsTransitionDuration(0)
      .pointsData(globePoints)
      .pointLat("lat")
      .pointLng("lng")
      .pointColor(fadedPointColor)
      .pointRadius("radius")
      .pointAltitude("altitude")
      .pointLabel("label")
      .arcsData(globeArcs)
      .arcStartLat((d) => d.startLat)
      .arcStartLng((d) => d.startLng)
      .arcEndLat((d) => d.endLat)
      .arcEndLng((d) => d.endLng)
      .arcColor((d) => d.color)
      .arcDashLength(0.4)
      .arcDashGap(0.2)
      .arcDashAnimateTime(1100)
      .arcStroke(0.5)
      .ringsData(globeRings)
      .ringLat((d) => d.lat)
      .ringLng((d) => d.lng)
      .ringColor((d) => () => d.color)
      .ringMaxRadius(3)
      .ringPropagationSpeed(2.5)
      .ringRepeatPeriod(1200);

    // Sem globeImageUrl (sem textura de foto da Terra) -- pinta o material
    // ja criado pela lib na cor de fundo do nosso tema, mantendo consistencia
    // visual com o mapa 2D (oceano escuro, paises em --land).
    const material = globeInstance.globeMaterial();
    material.color.set("#05070d");

    resizeGlobe();
    window.addEventListener("resize", resizeGlobe);

    globeFadeTimer = setInterval(tickGlobePoints, 100);
    globeInstance.pointOfView({ lat: 20, lng: 0, altitude: 2.2 }, 0);
    const controls = globeInstance.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.4;
    controls.enableZoom = true;
  }

  // Mesma ideia do fire2D (arco saindo da origem, pulso no impacto), so que
  // usando as propriedades reativas do globe.gl em vez de manipular SVG.
  function fire3D(ev) {
    const color = ev.color || "#33e0ff";
    const arc = {
      startLat: ev.sourceCoord[1],
      startLng: ev.sourceCoord[0],
      endLat: ev.targetCoord[1],
      endLng: ev.targetCoord[0],
      color,
    };
    globeArcs.push(arc);
    globeInstance.arcsData(globeArcs);

    const sourceRing = { lat: ev.sourceCoord[1], lng: ev.sourceCoord[0], color };
    globeRings.push(sourceRing);
    globeInstance.ringsData(globeRings);
    addGlobePoint(ev.sourceCoord, SOURCE_COLOR, eventTooltipHtml(ev));

    setTimeout(() => {
      const targetRing = { lat: ev.targetCoord[1], lng: ev.targetCoord[0], color: IMPACT_COLOR };
      globeRings.push(targetRing);
      globeInstance.ringsData(globeRings);
      addGlobePoint(ev.targetCoord, IMPACT_COLOR, countryName(ev.targetCountry));

      globeArcs = globeArcs.filter((a) => a !== arc);
      globeInstance.arcsData(globeArcs);

      setTimeout(() => {
        globeRings = globeRings.filter((r) => r !== targetRing);
        globeInstance.ringsData(globeRings);
      }, 1200);
    }, 1100);

    setTimeout(() => {
      globeRings = globeRings.filter((r) => r !== sourceRing);
      globeInstance.ringsData(globeRings);
    }, 1200);
  }

  async function switchView(mode) {
    if (mode === viewMode) return;
    document.querySelectorAll(".view-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.mode === mode);
    });

    if (mode === "3d") {
      const loadingEl = document.getElementById("globe-loading");
      if (!globeLibsLoaded) loadingEl.classList.remove("hidden");
      try {
        await ensureGlobeLibs();
        if (!globeInstance) initGlobe();
      } finally {
        loadingEl.classList.add("hidden");
      }
      document.getElementById("map").classList.add("hidden");
      document.getElementById("globe").classList.remove("hidden");
      document.getElementById("rotation-control").classList.remove("hidden");
      resizeGlobe();
    } else {
      document.getElementById("globe").classList.add("hidden");
      document.getElementById("map").classList.remove("hidden");
      document.getElementById("rotation-control").classList.add("hidden");
    }
    viewMode = mode;
  }

  function initViewToggle() {
    document.querySelectorAll(".view-btn").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.mode));
    });

    const speedInput = document.getElementById("rotation-speed");
    speedInput.addEventListener("input", () => {
      if (!globeInstance) return;
      const speed = parseFloat(speedInput.value);
      const controls = globeInstance.controls();
      controls.autoRotate = speed > 0;
      controls.autoRotateSpeed = speed;
    });
  }

  // Reproduz os eventos coletados em loop, ja que os dados brutos do DShield
  // so mudam a cada execucao do workflow. Cada "tick" dispara uma rajada de
  // 1 a 3 ataques (50% / 30% / 20%) escalonados em poucas centenas de ms, e
  // o intervalo entre ticks e curto -- ~2 eventos/s em media, o dobro do
  // ritmo anterior. Os eventos sao sorteados (e distintos dentro da rajada,
  // sem repetir os da rajada anterior) para a frequencia de cada pais-alvo
  // variar com o tempo e o ranking realmente embaralhar.
  const BURST_SIZES = [1, 1, 1, 1, 1, 2, 2, 2, 3, 3];
  const TICK_MIN_MS = 450;
  const TICK_MAX_MS = 1250;

  function startAnimationLoop(events) {
    if (!events.length) return;
    let lastBurst = [];

    function pickBurst() {
      const size = Math.min(
        BURST_SIZES[Math.floor(Math.random() * BURST_SIZES.length)],
        events.length
      );
      const avoidRecent = events.length > size + lastBurst.length;
      const picked = [];
      while (picked.length < size) {
        const idx = Math.floor(Math.random() * events.length);
        if (picked.includes(idx)) continue;
        if (avoidRecent && lastBurst.includes(idx)) continue;
        picked.push(idx);
      }
      return picked;
    }

    function tick() {
      const burst = pickBurst();
      burst.forEach((idx, i) => {
        setTimeout(() => fireEvent(events[idx]), i * (140 + Math.random() * 260));
      });
      lastBurst = burst;
      setTimeout(tick, TICK_MIN_MS + Math.random() * (TICK_MAX_MS - TICK_MIN_MS));
    }
    tick();
  }

  async function loadWorld() {
    const world = await d3.json("data/world-110m.json");
    const countries = topojson.feature(world, world.objects.countries);
    worldFeatures = countries.features;
    landLayer
      .selectAll("path")
      .data(countries.features)
      .join("path")
      .attr("class", "land")
      .attr("d", path);
  }

  async function loadAttacks() {
    const res = await fetch("data/attacks.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`Falha ao carregar attacks.json: ${res.status}`);
    return res.json();
  }

  async function loadCountryNames() {
    const res = await fetch("data/country-names-pt.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`Falha ao carregar country-names-pt.json: ${res.status}`);
    return res.json();
  }

  async function init() {
    initViewToggle();
    initPortsPeriodToggle();
    await loadWorld();
    try {
      const [data] = await Promise.all([
        loadAttacks(),
        loadCountryNames().then((names) => {
          countryNames = names;
        }),
      ]);
      liveData = data;
      hubList = buildHubList(data);
      portsHistory = data.portsHistory || null;
      updatedAtEl.textContent = `Fonte: ${data.source}`;
      renderAttackCounter(data.totalRecordsToday);
      renderPortList(data.ports || []);
      renderCveList(data.cves || []);
      countryTotals = buildInitialCountryTally(hubList, data.totalRecordsToday);
      renderCountryRanking(countryRankingArray());
      renderLegend(data.categories || []);
      renderUpdateTime(data.generatedAt);
      startAnimationLoop(data.events || []);
    } catch (err) {
      updatedAtEl.textContent = "nao foi possivel carregar data/attacks.json";
      console.error(err);
    }
  }

  init();
})();
