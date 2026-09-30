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

  const WIDTH = 960;
  const HEIGHT = 520;
  svg.attr("viewBox", `0 0 ${WIDTH} ${HEIGHT}`);

  const projection = d3.geoNaturalEarth1().fitSize([WIDTH, HEIGHT], { type: "Sphere" });
  const path = d3.geoPath(projection);

  const landLayer = svg.append("g").attr("class", "land-layer");
  const hubLayer = svg.append("g").attr("class", "hub-layer");
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

  // Ponto de entrada unico chamado pelo loop de animacao: atualiza os
  // paineis (sempre) e delega o efeito visual no mapa para o modo ativo.
  function fireEvent(ev) {
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
        travelDot.remove();
      });

    impactPulse(ev.sourceCoord, color);
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
      .map((t) => `<span class="threat-tag" title="Visto pela ultima vez em ${t.lastSeen || "?"}">${t.label}</span>`)
      .join("")}</div>`;
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
  // Os 12 hubs de destino ilustrativos sao uma fatia pequena perto dos 200+
  // paises do mundo real -- a soma deles nao deveria bater no contador
  // principal (isso exigiria numeros irreais por pais). Em vez disso, mira
  // numa fracao plausivel do total (os "12 mais" concentrando uma parcela
  // desproporcional do volume, como costuma acontecer na pratica), com
  // pesos aleatorios e desiguais entre os paises em vez de uma faixa fixa
  // desconectada do contador.
  const COUNTRY_SHARE_OF_TOTAL = 0.12;

  function buildInitialCountryTally(events, totalRecordsToday) {
    const countries = [...new Set(events.map((ev) => ev.targetCountry).filter(Boolean))];
    const map = new Map();
    if (!countries.length) return map;

    const targetSum = (totalRecordsToday || 0) * COUNTRY_SHARE_OF_TOTAL;
    if (!targetSum) {
      // Sem contador disponivel: mantem numeros pequenos e embaralhados.
      countries.forEach((c) => map.set(c, 5 + Math.floor(Math.random() * 40)));
      return map;
    }

    // Pesos com variancia realista (alguns paises concentram bem mais que
    // outros) em vez de distribuir o total igualmente entre os 12.
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

  function renderHubs(events) {
    const hubs = new Map();
    for (const ev of events) {
      if (!hubs.has(ev.targetHub)) hubs.set(ev.targetHub, ev.targetCoord);
    }
    hubLayer
      .selectAll(".hub")
      .data([...hubs.entries()], (d) => d[0])
      .join("circle")
      .attr("class", "hub")
      .attr("r", 5)
      .attr("cx", (d) => projection(d[1])[0])
      .attr("cy", (d) => projection(d[1])[1]);
  }

  function renderSourceDots(events) {
    dotLayer
      .selectAll(".source-dot")
      .data(events, (d) => d.id)
      .join("circle")
      .attr("class", "source-dot")
      .attr("r", 2.2)
      .attr("cx", (d) => projection(d.sourceCoord)[0])
      .attr("cy", (d) => projection(d.sourceCoord)[1])
      .on("mousemove", (event, d) => {
        showTooltip(
          `<div class="attack-line">${flagSpan(d.country)}<strong style="color:${d.color || "#33e0ff"}">${d.attackType || "?"}</strong>${flagSpan(d.targetCountry)}</div>` +
            `${countryName(d.country)} &middot; ${d.ip}<br/>${d.reports.toLocaleString("pt-BR")} registros${threatTagsHtml(d.threatTags)}`,
          [event.offsetX, event.offsetY]
        );
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

  function buildGlobePoints(events) {
    const points = events.map((ev) => ({
      lat: ev.sourceCoord[1],
      lng: ev.sourceCoord[0],
      color: ev.color || "#33e0ff",
      radius: 0.35,
      altitude: 0.01,
      label: `<div class="attack-line">${flagSpan(ev.country)}<strong style="color:${ev.color || "#33e0ff"}">${ev.attackType || "?"}</strong>${flagSpan(ev.targetCountry)}</div>${countryName(ev.country)} &middot; ${ev.ip}<br/>${ev.reports.toLocaleString("pt-BR")} registros${threatTagsHtml(ev.threatTags)}`,
    }));

    const hubs = new Map();
    for (const ev of events) {
      if (!hubs.has(ev.targetHub)) {
        hubs.set(ev.targetHub, {
          lat: ev.targetCoord[1],
          lng: ev.targetCoord[0],
          color: "#7c88a6",
          radius: 0.55,
          altitude: 0.012,
          label: countryName(ev.targetCountry),
        });
      }
    }
    return points.concat([...hubs.values()]);
  }

  function resizeGlobe() {
    if (!globeInstance) return;
    const el = document.getElementById("globe");
    globeInstance.width(el.clientWidth).height(el.clientHeight);
  }

  function initGlobe(events) {
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
      .pointsData(buildGlobePoints(events))
      .pointLat("lat")
      .pointLng("lng")
      .pointColor("color")
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

    globeInstance.pointOfView({ lat: 20, lng: 0, altitude: 2.2 }, 0);
    const controls = globeInstance.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.4;
    controls.enableZoom = true;
  }

  // Cor neutra para o pulso de chegada no hub -- o hub e so um ponto de
  // referencia ilustrativo, nao deve "emitir" a cor do tipo de ataque como
  // se ele proprio fosse a origem ou o tipo do ataque.
  const HUB_PULSE_COLOR = "#7c88a6";

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

    setTimeout(() => {
      const targetRing = { lat: ev.targetCoord[1], lng: ev.targetCoord[0], color: HUB_PULSE_COLOR };
      globeRings.push(targetRing);
      globeInstance.ringsData(globeRings);

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
        if (!globeInstance) initGlobe((liveData && liveData.events) || []);
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

  // Reproduz os eventos coletados em loop, com atraso aleatorio entre cada
  // disparo, ja que os dados brutos do DShield so mudam a cada ~15 minutos.
  // Sorteia o proximo ataque em vez de seguir sempre a mesma sequencia --
  // assim a frequencia de cada pais-alvo varia com o tempo (em vez de todos
  // andarem em lockstep, um atras do outro) e o ranking realmente embaralha.
  function startAnimationLoop(events) {
    if (!events.length) return;
    let lastIndex = -1;
    function tick() {
      let idx = Math.floor(Math.random() * events.length);
      if (events.length > 1 && idx === lastIndex) {
        idx = (idx + 1) % events.length;
      }
      lastIndex = idx;
      fireEvent(events[idx]);
      setTimeout(tick, 500 + Math.random() * 1100);
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
      portsHistory = data.portsHistory || null;
      updatedAtEl.textContent = `Fonte: ${data.source}`;
      renderAttackCounter(data.totalRecordsToday);
      renderPortList(data.ports || []);
      renderCveList(data.cves || []);
      countryTotals = buildInitialCountryTally(data.events || [], data.totalRecordsToday);
      renderCountryRanking(countryRankingArray());
      renderLegend(data.categories || []);
      renderUpdateTime(data.generatedAt);
      renderHubs(data.events || []);
      renderSourceDots(data.events || []);
      startAnimationLoop(data.events || []);
    } catch (err) {
      updatedAtEl.textContent = "nao foi possivel carregar data/attacks.json";
      console.error(err);
    }
  }

  init();
})();
