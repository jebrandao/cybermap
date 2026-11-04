#!/usr/bin/env node
// Diagnostico: confere se o token da Cloudflare funciona e mostra o formato da
// resposta do ranking de paises-alvo do Radar. Nao grava nada e nao imprime o
// token.
// Uso: node scripts/check-cloudflare.mjs
// O token vem de CLOUDFLARE_API_TOKEN ou e pedido no terminal (digitacao oculta).

const API = "https://api.cloudflare.com/client/v4";

function askHidden(question) {
  return new Promise((resolve) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let value = "";
    stdin.on("data", function onData(chunk) {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stdout.write("\n");
          return resolve(value.trim());
        }
        if (ch === "\u0003") process.exit(130);
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    });
  });
}

// Garantia extra: nunca deixa um valor parecido com token chegar ao terminal.
function redact(text) {
  return text.replace(/cf[a-z]{1,3}_[A-Za-z0-9]{20,}/g, "[token omitido]");
}

async function call(token, path) {
  const res = await fetch(`${API}${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  const text = await res.text();
  return { status: res.status, text };
}

async function main() {
  const token = process.env.CLOUDFLARE_API_TOKEN || (await askHidden("Cole o token (nao aparece na tela) e tecle Enter: "));
  if (!token) {
    console.error("Nenhum token informado.");
    process.exit(1);
  }
  console.log(`Token recebido: ${token.length} caracteres.\n`);

  const checks = [
    ["1) Validar token", "/user/tokens/verify"],
    ["2) Radar - alvos de DDoS camada 7 (24h)", "/radar/attacks/layer7/top/locations/target?dateRange=1d&limit=10&format=json"],
    ["3) Radar - alvos de DDoS camada 3 (24h)", "/radar/attacks/layer3/top/locations/target?dateRange=1d&limit=10&format=json"],
  ];
  for (const [title, path] of checks) {
    try {
      const { status, text } = await call(token, path);
      console.log(`${title} -> HTTP ${status}`);
      console.log(redact(text).slice(0, 1800));
    } catch (err) {
      console.log(`${title} -> falhou: ${err.message}`);
    }
    console.log();
  }
}

main();
