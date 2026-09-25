# CyberMap

Mapa 2D de ataques cibernéticos, inspirado no [Kaspersky Cyberthreat Map](https://cybermap.kaspersky.com/), construído para rodar 100% estático no GitHub Pages.

## Como funciona

- **Fonte de dados**: [DShield / SANS Internet Storm Center](https://isc.sans.edu/api/) — API pública, sem chave, com dados agregados de scans/ataques reportados por uma rede voluntária de sensores.
- **Coleta**: `scripts/fetch-dshield.mjs` roda via GitHub Actions (`.github/workflows/update-data.yml`) a cada 15 minutos, busca as top portas e IPs atacantes, resolve o país de cada IP e grava tudo em `data/attacks.json`.
- **Visualização**: `src/app.js` usa D3.js para desenhar um mapa-múndi (`data/world-110m.json`) e animar arcos entre o país de origem e pontos de destino estilizados.

## Limitações importantes (leia antes de divulgar como "tempo real")

- O DShield não expõe a localização real dos sensores/alvos por privacidade. Os pontos de **destino** no mapa são ilustrativos (hubs fixos), não geografia real.
- Os dados da API já vêm com cache de 10 minutos no servidor deles; por isso a atualização é a cada 15 min, não por segundo. A animação no front-end reproduz os eventos coletados em loop para dar sensação de continuidade.
- A localização de **origem** é o país do IP (via ASN), não a cidade exata.
- Respeite a política de uso da API: identifique-se com um `User-Agent` contendo um contato válido (veja abaixo).

## Configuração antes de publicar

1. Defina o contato exigido pelo DShield. Duas opções:
   - Crie uma variável de repositório `DSHIELD_CONTACT` (Settings → Secrets and variables → Actions → Variables) com algo como `github.com/seu-usuario/seu-repo`.
   - Ou deixe o padrão, que usa `${{ github.repository }}` automaticamente (já configurado no workflow).
2. Habilite permissão de escrita para o workflow: Settings → Actions → General → Workflow permissions → **Read and write permissions**.
3. Ative o GitHub Pages: Settings → Pages → Source → `Deploy from a branch` → branch `main`, pasta `/ (root)`.

## Rodando localmente

```bash
npm run fetch-data          # gera data/attacks.json com dados atuais
npx serve .                 # ou: python -m http.server 8080
```

Depois abra `http://localhost:8080` (ou a porta usada pelo servidor escolhido).

## Estrutura

```
index.html              página principal
style.css                tema escuro
src/app.js                lógica do mapa (D3)
data/world-110m.json      topologia do mapa-múndi (world-atlas, 110m)
data/country-centroids.json  país -> [lon, lat] para posicionar os pontos
data/attacks.json         gerado pelo workflow (dados do DShield)
scripts/fetch-dshield.mjs  coleta e transforma os dados do DShield
.github/workflows/update-data.yml  cron do GitHub Actions
```
