# IoT-NIDS — IoT Anomaly Detection

Web application for experimenting with machine-learning-based anomaly detection in IoT data.

The application provides two independent training modes:

- **Client Training** — TensorFlow.js runs locally in the browser using the embedded demo dataset.
- **Server Training** — a labeled CSV is uploaded to a Python/FastAPI backend, where a Random Forest or XGBoost model is trained and evaluated.

The project is intended for educational and experimental use.

## Architecture

```text
                    IoT-NIDS
                       |
          +------------+------------+
          |                         |
   Client Training             Server Training
          |                         |
   TensorFlow.js                FastAPI / Python
   Browser                     Uploaded CSV
   Embedded JSON               Preprocessing
   Neural network              80/20 train/test split
   Local prediction            Random Forest / XGBoost
```

In **Client Training**, training and prediction are performed locally in the browser and data is not sent to the backend.

In **Server Training**, uploaded training and prediction CSV files are sent to the Python backend.

## Requirements

Before running the project, install:

- **Node.js 20.12 or newer**
- **npm**
- **Python 3.10 or newer**
- Python `venv`

On Ubuntu/Debian, if `python3 -m venv` is unavailable:

```bash
sudo apt update
sudo apt install python3-venv
```

For systems where the version-specific package is required, for example Python 3.10:

```bash
sudo apt install python3.10-venv
```

## Installation

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd iot-anomaly-detection
```

If you downloaded the project as a ZIP, extract it and open a terminal in the directory containing `package.json`.

### 1. Frontend

Install JavaScript dependencies:

```bash
npm install
```

Create a `.env` file in the project root if one does not already exist:

```env
VITE_API_URL=http://localhost:8000
```

Start the Vite development server:

```bash
npm run dev
```

The frontend is normally available at:

```text
http://localhost:5173
```

Keep this terminal running.

### 2. Backend

Open a second terminal and enter the backend directory:

```bash
cd backend
```

Create a Python virtual environment:

```bash
python3 -m venv venv
```

Activate it on Linux/macOS:

```bash
source venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Start FastAPI:

```bash
python -m uvicorn main:app --reload
```

The backend is normally available at:

```text
http://127.0.0.1:8000
```

Interactive FastAPI/Swagger documentation:

```text
http://127.0.0.1:8000/docs
```

## Running the complete application

Two terminals should be running at the same time.

**Terminal 1 — backend**

```bash
cd backend
source venv/bin/activate
python -m uvicorn main:app --reload
```

**Terminal 2 — frontend**

```bash
npm run dev
```

Then open:

```text
http://localhost:5173
```

## Training modes

### Client Training

Client Training is the original browser-based demonstration.

It uses:

- React
- TensorFlow.js
- an embedded, filtered ToN-IoT sample
- browser-side preprocessing and model training
- browser-side CSV prediction

The neural network is trained directly in the browser. The FastAPI backend is not required for this mode.

This mode demonstrates the possibility of performing lightweight ML processing locally on the client.

### Server Training

Server Training is designed for larger and more flexible experiments.

Workflow:

```text
Training CSV
    |
    v
FastAPI backend
    |
    v
Cleaning and preprocessing
    |
    v
Automatic numeric/categorical feature detection
    |
    v
Missing-value handling + categorical encoding
    |
    v
Stratified 80/20 train/test split
    |
    v
Random Forest / XGBoost
    |
    v
Evaluation metrics + saved model
```

The user can choose:

- **Random Forest**
- **XGBoost**

The backend returns metrics including:

- Accuracy
- Precision
- Recall
- F1 score
- ROC-AUC
- number of cleaned rows
- number of input features
- train/test sizes
- training time

### Training CSV requirements

The current Server Training implementation expects a labeled CSV containing:

```text
label
```

with binary values:

```text
0 = normal
1 = anomaly / attack
```

Other feature columns may be numeric or categorical. The backend automatically detects their types, handles missing values and encodes categorical features.

For example:

```csv
duration,src_bytes,dst_bytes,proto,label
0.12,120,340,tcp,0
1.43,9500,120,tcp,1
0.08,85,220,udp,0
```

The server is not restricted to the original ToN-IoT Network CSV. Other labeled datasets can be used when they satisfy the expected binary `label` format.

Examples include appropriately structured ToN-IoT datasets such as Network, Fridge, Garage Door, GPS Tracker, Modbus, Motion Light, Thermostat and Weather.

Other datasets may also be used after their target class has been converted to the expected binary `label` representation.

## Why the dataset is split 80/20

Server Training uses a **stratified 80/20 split**:

- 80% of rows are used to train the model.
- 20% are kept unseen during training and used to evaluate it.

Stratification preserves approximately the same class distribution in both subsets.

The evaluation metrics displayed after training are calculated on the held-out 20% test subset.

## Prediction

After Server Training finishes, the trained model receives an ID and is stored by the backend.

A second CSV can then be uploaded in the **Prediction dataset** section.

```text
Prediction CSV
      |
      v
Saved preprocessing pipeline
      |
      v
Saved trained model
      |
      v
Normal / anomalous prediction
```

The prediction CSV must contain the same feature schema expected by the model that was trained.

The columns `label` and `type` are optional during prediction and are not used as input features.

The result shows:

- number of analyzed rows
- number of normal rows
- number of anomalous rows
- anomaly rate
- per-row predictions and anomaly probabilities returned by the API

## API

### Health check

```text
GET /api/health
```

### Train a model

```text
POST /api/train
```

Multipart form fields:

```text
file        Training CSV
model_type  random_forest | xgboost
```

### Predict

```text
POST /api/predict
```

Multipart form fields:

```text
model_id    ID returned by /api/train
file        Prediction CSV
```

## Project structure

```text
iot-anomaly-detection/
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   └── models/
├── public/
├── src/
│   ├── IoTAnomalyML.jsx
│   ├── ServerTrainingPanel.jsx
│   └── ...
├── .env
├── package.json
├── vite.config.js
└── README.md
```

## ToN-IoT data

The original ToN-IoT datasets are not committed to this repository because some CSV files are large.

Download the required dataset separately from the official ToN-IoT dataset source and upload it through the application.

Large generated or source CSV files should remain excluded from Git, for example:

```gitignore
thesis_data/*.csv
```

## Troubleshooting

### `crypto.getRandomValues is not a function`

Check your Node.js version:

```bash
node -v
```

Use Node.js 20.12+ and reinstall dependencies:

```bash
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### `ensurepip is not available`

Install Python venv support:

```bash
sudo apt install python3-venv
```

Then recreate the environment:

```bash
rm -rf backend/venv
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### `ModuleNotFoundError: No module named 'app'`

This project uses:

```text
backend/main.py
```

so start the server from the `backend` directory with:

```bash
python -m uvicorn main:app --reload
```

not `app.main:app`.

### Frontend cannot connect to backend

Check that FastAPI is running on port 8000 and that the frontend `.env` contains:

```env
VITE_API_URL=http://localhost:8000
```

Restart Vite after changing `.env`.

## Technologies

### Frontend

- React
- Vite
- Tailwind CSS
- TensorFlow.js
- PapaParse
- Recharts

### Backend

- FastAPI
- pandas
- NumPy
- scikit-learn
- XGBoost
- joblib
- Uvicorn

## Notes

The application is a machine-learning demonstration and research prototype. Predictions should not be treated as a replacement for a production intrusion detection system or professional security monitoring.

## Server security and resource limits

The public Server Training API is intentionally resource-limited because model training is CPU- and memory-intensive.

Default limits:

```text
Maximum upload size:       700 MB
Maximum rows:              500,000
Maximum columns:           1,000
Maximum encoded features:  50,000
Concurrent training jobs:  2
Training timeout:          15 minutes
Model retention:           24 hours
Training rate limit:       10 requests/hour/IP
Prediction rate limit:     120 requests/hour/IP
```

Additional protections include:

- `.csv` extension and parse validation
- row and column validation before ML training
- rejection of extreme one-hot feature expansion
- server-generated model IDs
- model ID format validation
- automatic deletion of expired model files
- CORS restricted to configured frontend origins
- bounded CPU usage (`n_jobs=1`)
- generic client-facing errors instead of Python tracebacks
- prediction schema validation

All values can be changed through `backend/.env`.

Important: reverse proxies and hosting providers may impose their own request-size and timeout limits. A backend configured for 700 MB uploads still requires a hosting platform that supports requests of that size.

For a production deployment behind a proxy/load balancer, configure trusted proxy handling so FastAPI/Uvicorn receives the real client IP before relying on per-IP rate limiting.
