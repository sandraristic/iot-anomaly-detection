# IoT Anomaly Detection Platform

Web application for experimenting with machine-learning-based anomaly detection in IoT network data.

The platform supports two independent machine learning modes:

- **Client Training** — a neural network is trained directly in the browser using TensorFlow.js and an embedded ToN-IoT sample.
- **Server Training** — a user-provided labeled CSV dataset is sent to a Python/FastAPI backend, where a Random Forest or XGBoost model is trained and evaluated.

The project was developed as part of a master's thesis focused on the development of an IoT analytics platform for anomaly detection in smart-device network traffic.

## Live application

https://iot-anomaly-detection.vercel.app/

## Architecture

```text
                           User
                             |
                             v
                    React / Vite frontend
                        deployed on Vercel
                             |
                +------------+------------+
                |                         |
                v                         v
         Client Training            Server Training
                |                         |
         TensorFlow.js                REST API
         Browser                     FastAPI / Python
         Embedded ToN-IoT sample          |
         Neural network                   v
         Local prediction          CSV preprocessing
                                   80/20 train/test split
                                   Random Forest / XGBoost
                                          |
                                          v
                                 Evaluation / Prediction
```

The client-side and server-side modes are independent.

In **Client Training**, training and prediction are performed locally in the user's browser. The backend is not required for this mode.

In **Server Training**, training and prediction datasets are uploaded to the backend for preprocessing and machine learning processing.

## Main features

### Client Training

The client-side mode demonstrates lightweight machine learning directly in the browser.

It includes:

- TensorFlow.js neural network training
- embedded, preprocessed ToN-IoT sample
- live training progress
- accuracy and loss visualization
- accuracy, precision, recall and F1 score
- ROC curve and AUC
- confusion matrix
- permutation feature importance
- CSV upload and anomaly prediction
- local model storage using IndexedDB

The browser model uses a reduced dataset because training the complete prepared ToN-IoT dataset directly in the browser would require significantly more computational resources.

### Server Training

The server-side mode enables training on user-uploaded labeled CSV datasets.

The user can select:

- **Random Forest**
- **XGBoost**

The training workflow is:

```text
Training CSV
    |
    v
FastAPI backend
    |
    v
Data cleaning and preprocessing
    |
    v
Numeric / categorical feature detection
    |
    v
Missing-value handling
    |
    v
Categorical encoding
    |
    v
Stratified 80/20 train/test split
    |
    v
Random Forest / XGBoost
    |
    v
Evaluation metrics + trained model
```

After training, the backend returns information including:

- Accuracy
- Precision
- Recall
- F1 score
- ROC-AUC
- number of processed rows
- number of input features
- training set size
- test set size
- training time

The trained model receives a unique model ID that can later be used for prediction.

## Prediction

After Server Training is completed, the user can upload another CSV dataset and apply the trained model to new data.

The prediction workflow is:

```text
Prediction CSV
      |
      v
Saved preprocessing pipeline
      |
      v
Previously trained model
      |
      v
Normal / anomalous prediction
```

The prediction dataset must contain the feature structure expected by the trained model.

The result includes:

- number of analyzed rows
- number of rows classified as normal
- number of rows classified as anomalous
- anomaly rate
- individual predictions
- anomaly probabilities

## Training CSV format

Server Training expects a labeled CSV dataset containing a binary target column:

```text
label
```

Expected values:

```text
0 = normal
1 = anomaly / attack
```

Feature columns may contain numerical or categorical data. The backend automatically detects data types, handles missing values and encodes categorical features.

Example:

```csv
duration,src_bytes,dst_bytes,proto,label
0.12,120,340,tcp,0
1.43,9500,120,tcp,1
0.08,85,220,udp,0
```

The server is not limited exclusively to one ToN-IoT CSV file. Other appropriately prepared datasets can also be used if the target variable follows the expected binary `label` format.

## Why an 80/20 split is used

Server Training uses a stratified 80/20 train/test split:

- 80% of the dataset is used for model training.
- 20% is kept unseen during training and used for evaluation.

Stratification preserves approximately the same class distribution in both subsets.

All evaluation metrics displayed after server training are calculated on the held-out test subset.

## API

### Health check

```http
GET /api/health
```

### Train model

```http
POST /api/train
```

Multipart form fields:

```text
file        Training CSV
model_type  random_forest | xgboost
```

### Prediction

```http
POST /api/predict
```

Multipart form fields:

```text
model_id    ID returned by /api/train
file        Prediction CSV
```

## Technologies

### Frontend

- React
- Vite
- Tailwind CSS
- TensorFlow.js
- PapaParse
- Recharts

### Backend

- Python
- FastAPI
- pandas
- NumPy
- scikit-learn
- XGBoost
- joblib
- Uvicorn

### Deployment

- **Frontend:** Vercel
- **Backend:** Render
- **Source control:** Git / GitHub

## Requirements

Before running the project locally, install:

- Node.js 20.12 or newer
- npm
- Python 3.10 or newer
- Python `venv`

## Local installation

Clone the repository:

```bash
git clone https://github.com/sandraristic/iot-anomaly-detection.git
cd iot-anomaly-detection
```

### Frontend

Install dependencies:

```bash
npm install
```

Create a `.env` file in the project root:

```env
VITE_API_URL=http://localhost:8000
```

Start the frontend:

```bash
npm run dev
```

The application is normally available at:

```text
http://localhost:5173
```

### Backend

Open another terminal:

```bash
cd backend
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it on Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI server:

```bash
python -m uvicorn main:app --reload
```

The backend is normally available at:

```text
http://127.0.0.1:8000
```

Interactive API documentation is available at:

```text
http://127.0.0.1:8000/docs
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
├── .env.example
├── package.json
├── vite.config.js
└── README.md
```

## ToN-IoT data

Large original ToN-IoT CSV datasets are not committed to this repository.

Datasets required for experiments should be downloaded separately from the official ToN-IoT source and uploaded through the application when using Server Training.

Generated and source CSV files should remain excluded from Git when they are too large for normal repository storage.

## Server resource limits

The public backend is resource-limited because model training can require significant CPU and memory resources.

The application includes protections such as:

- upload and CSV validation
- row and column limits
- protection against excessive categorical feature expansion
- server-generated model identifiers
- validation of prediction schemas
- automatic removal of expired models
- restricted CORS configuration
- bounded CPU usage
- training and prediction rate limits
- generic client-facing error messages

Hosting platform limits may additionally restrict request size, execution time or available resources.

## Disclaimer

This application is an educational and research prototype for experimenting with machine-learning-based anomaly detection.

It is **not intended to replace a production intrusion detection system or professional security monitoring solution**.

## Master's thesis

The platform was developed as the practical component of the master's thesis:

**„Развој IoT аналитичке платформе за детекцију аномалија у мрежном саобраћају паметних уређаја“**

The implementation demonstrates both client-side and server-side approaches to machine learning for IoT network anomaly detection.

## License

This project is available under the MIT License.
