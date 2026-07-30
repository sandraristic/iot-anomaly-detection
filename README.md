# IoT-NIDS

A web app that trains and runs a neural network directly in the browser to detect
anomalies in IoT device network traffic, using TensorFlow.js and a sample from the
ToN-IoT dataset. No backend, no data leaves your machine.

## Features

- Live, in-browser neural network training (no backend required)
- Real-time training curves, metrics, and ROC curve (with AUC)
- Live predictions on random samples and permutation feature importance
- Import your own CSV to analyze new traffic — auto-detects both pre-encoded
  columns and raw Zeek-style column names (e.g. `id.resp_p`, `orig_bytes`)
- Downloadable CSV template and full results export
- Model persists locally (IndexedDB) — no retraining on repeat visits
- English / Serbian language toggle
- Light / dark theme

## Tech Stack

React · TensorFlow.js · Recharts · PapaParse · Tailwind CSS

## Getting Started

```bash
npm install
npm run dev
```

Requires Node.js 20.12+.

## CSV Import Format

At minimum, the file needs these numeric columns:

```
dst_port, src_ip_bytes, src_pkts, dst_ip_bytes, dst_pkts, src_bytes
```

Optionally, include `proto`, `service`, `conn_state`, and `dns_query` (raw values
like `"tcp"`, `"dns"`, `"REJ"`) — the app derives the remaining engineered
features automatically. Zeek-style names (`id.resp_p`, `orig_bytes`,
`orig_pkts`, `resp_ip_bytes`, ...) are also recognized. A downloadable example
is available in the app itself.

## Data Source

[ToN-IoT dataset](https://research.unsw.edu.au/projects/toniot-datasets) — Moustafa, N. et al.

## Disclaimer

This model is trained on a research dataset and is intended for educational /
demonstration purposes. It is not a substitute for a production security system.

## License

MIT
