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

  // Desenha o caminho do ataque: a linha "revela" do zero ate o comprimento
  // total (dash-offset) enquanto um ponto percorre o mesmo trajeto, saindo
  // da origem e chegando ao destino, como no cybermap da Kaspersky.
  function fireEvent(ev) {
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
    prependEventToList(ev);
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
      </div>`;
    eventListEl.prepend(li);
    while (eventListEl.children.length > 14) {
      eventListEl.removeChild(eventListEl.lastChild);
    }
  }

  function renderPortList(ports) {
    portListEl.innerHTML = "";
    ports
      .slice()
      .sort((a, b) => b.records - a.records)
      .slice(0, 8)
      .forEach((p) => {
        const li = document.createElement("li");
        li.innerHTML = `<span>porta ${p.port}</span><span class="count">${p.records.toLocaleString("pt-BR")}</span>`;
        portListEl.appendChild(li);
      });
  }

  function renderCountryRanking(ranking) {
    countryRankingEl.innerHTML = "";
    if (!ranking.length) {
      countryRankingEl.innerHTML = '<li class="event-meta">sem dados</li>';
      return;
    }
    ranking.forEach((r) => {
      const li = document.createElement("li");
      li.innerHTML = `
        <span class="rank-flag">${flagSpan(r.country)}<span class="rank-country">${countryName(r.country)}</span></span>
        <span class="count">${r.reports.toLocaleString("pt-BR")}</span>`;
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
            `${countryName(d.country)} &middot; ${d.ip}<br/>${d.reports.toLocaleString("pt-BR")} registros`,
          [event.offsetX, event.offsetY]
        );
      })
      .on("mouseleave", hideTooltip);
  }

  // Reproduz os eventos coletados em loop, com atraso aleatorio entre cada
  // disparo, ja que os dados brutos do DShield so mudam a cada ~15 minutos.
  function startAnimationLoop(events) {
    if (!events.length) return;
    let i = 0;
    function tick() {
      fireEvent(events[i % events.length]);
      i++;
      setTimeout(tick, 500 + Math.random() * 1100);
    }
    tick();
  }

  async function loadWorld() {
    const world = await d3.json("data/world-110m.json");
    const countries = topojson.feature(world, world.objects.countries);
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
    await loadWorld();
    try {
      const [data] = await Promise.all([
        loadAttacks(),
        loadCountryNames().then((names) => {
          countryNames = names;
        }),
      ]);
      updatedAtEl.textContent = `Fonte: ${data.source}`;
      renderPortList(data.ports || []);
      renderCveList(data.cves || []);
      renderCountryRanking(data.countryRanking || []);
      renderLegend(data.categories || []);
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
