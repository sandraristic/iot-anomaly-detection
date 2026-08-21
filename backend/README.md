# Server-side ML backend

This FastAPI service extends the original browser-only demo with server-side training on an uploaded, labeled ToN-IoT-compatible CSV.

## Run locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

In another terminal:

```bash
cp .env.example .env
npm install
npm run dev
```

The frontend reads `VITE_API_URL` (default: `http://localhost:8000`).

## API

- `POST /api/train`: multipart fields `file` and `model_type` (`random_forest` or `xgboost`). Training CSV must contain `label`; `type` is used for stratification when available.
- `POST /api/predict`: multipart fields `file` and `model_id`. Uses the raw feature schema learned during server training.
- `GET /api/health`

## Thesis preprocessing alignment

The server repeats the core rules from the thesis scripts: duplicate removal, removal of columns with >95% `-`, removal of `ts/src_ip/dst_ip`, creation of `has_dns_query`, and removal of `src_port/dns_query`. Categorical variables are encoded server-side with `OneHotEncoder(handle_unknown="ignore")` so the same fitted preprocessing is reused for prediction.

## Deployment note

Long-running training and persisted model files are a poor fit for serverless functions. Deploy this backend to a persistent Python service/container and set `CORS_ORIGINS` plus the frontend's `VITE_API_URL` accordingly.
