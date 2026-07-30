# IoT-NIDS

A web app that trains and runs a neural network directly in the browser to detect
anomalies in IoT device network traffic, using TensorFlow.js and the ToN-IoT
dataset.


## Features

- Live, in-browser neural network training (no backend required)
- Real-time training curves and metrics
- Live predictions and permutation feature importance
- Import your own CSV for analyzing new traffic
- Model persists locally (IndexedDB) — no retraining on repeat visits

## Tech Stack

React · TensorFlow.js · Recharts · PapaParse · Tailwind CSS

## Getting Started

```bash
npm install
npm run dev
```

Requires Node.js 20.12+.

## CSV Import Format

The CSV file should contain the following columns:

```
dst_port, src_ip_bytes, src_pkts, proto_tcp, proto_udp, dst_ip_bytes,
dst_pkts, conn_state_REJ, conn_state_OTH, src_bytes, service_dns,
has_dns_query, dns_rejected_F, dns_RD_F
```

## Data Source

[ToN-IoT dataset](https://research.unsw.edu.au/projects/toniot-datasets) — Moustafa, N. et al.

## License

MIT
