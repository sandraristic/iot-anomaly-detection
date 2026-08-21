from __future__ import annotations

import asyncio
import io
import os
import re
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier


APP_DIR = Path(__file__).resolve().parent
MODEL_DIR = APP_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Security/resource limits
# ---------------------------------------------------------------------------
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(700 * 1024 * 1024)))  # 700 MB
MAX_TRAIN_ROWS = int(os.getenv("MAX_TRAIN_ROWS", "500000"))
MAX_PREDICT_ROWS = int(os.getenv("MAX_PREDICT_ROWS", "500000"))
MAX_COLUMNS = int(os.getenv("MAX_COLUMNS", "1000"))

# Protect against an extreme one-hot expansion (e.g. many high-cardinality columns).
MAX_ENCODED_FEATURES = int(os.getenv("MAX_ENCODED_FEATURES", "50000"))

MAX_CONCURRENT_TRAININGS = int(os.getenv("MAX_CONCURRENT_TRAININGS", "2"))
TRAIN_TIMEOUT_SECONDS = int(os.getenv("TRAIN_TIMEOUT_SECONDS", "900"))  # 15 min
MODEL_RETENTION_SECONDS = int(os.getenv("MODEL_RETENTION_SECONDS", "86400"))  # 24 h

TRAIN_RATE_LIMIT = int(os.getenv("TRAIN_RATE_LIMIT", "10"))  # requests/window/IP
TRAIN_RATE_WINDOW_SECONDS = int(os.getenv("TRAIN_RATE_WINDOW_SECONDS", "3600"))
PREDICT_RATE_LIMIT = int(os.getenv("PREDICT_RATE_LIMIT", "120"))
PREDICT_RATE_WINDOW_SECONDS = int(os.getenv("PREDICT_RATE_WINDOW_SECONDS", "3600"))

MODEL_ID_RE = re.compile(r"^[a-f0-9]{12}$")

training_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TRAININGS)
rate_buckets: dict[str, deque[float]] = defaultdict(deque)

app = FastAPI(
    title="IoT-NIDS Server Training API",
    version="1.1.0",
    docs_url="/docs",
    redoc_url=None,
)

origins = [
    x.strip()
    for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if x.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def _client_ip(request: Request) -> str:
    # When deployed behind a trusted proxy, configure the proxy/server so request.client
    # contains the real client address. We intentionally do not trust arbitrary X-Forwarded-For.
    return request.client.host if request.client else "unknown"


def _check_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    now = time.time()
    bucket = rate_buckets[key]
    cutoff = now - window_seconds
    while bucket and bucket[0] < cutoff:
        bucket.popleft()

    if len(bucket) >= limit:
        retry_after = max(1, int(window_seconds - (now - bucket[0])))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in about {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    bucket.append(now)


def _cleanup_expired_models() -> None:
    now = time.time()
    for path in MODEL_DIR.glob("*.joblib"):
        try:
            if now - path.stat().st_mtime > MODEL_RETENTION_SECONDS:
                path.unlink(missing_ok=True)
        except OSError:
            pass


def _validate_model_id(model_id: str) -> None:
    if not MODEL_ID_RE.fullmatch(model_id):
        raise HTTPException(400, "Invalid model ID.")


def _validate_csv_upload(file: UploadFile) -> int:
    filename = (file.filename or "").strip()
    if not filename.lower().endswith(".csv"):
        raise HTTPException(400, "Please upload a .csv file.")

    # UploadFile is already spooled by Starlette. Checking its file size avoids loading
    # the whole upload into Python memory just to enforce the limit.
    try:
        current = file.file.tell()
        file.file.seek(0, os.SEEK_END)
        size = file.file.tell()
        file.file.seek(current)
    except Exception as exc:
        raise HTTPException(400, "Could not inspect uploaded file.") from exc

    if size <= 0:
        raise HTTPException(400, "The uploaded CSV is empty.")
    if size > MAX_UPLOAD_BYTES:
        max_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
        actual_mb = size / (1024 * 1024)
        raise HTTPException(
            413,
            f"CSV is {actual_mb:.1f} MB. Maximum allowed upload size is {max_mb:.0f} MB.",
        )

    return size


def _read_csv_limited(file: UploadFile, max_rows: int) -> pd.DataFrame:
    """Parse CSV while enforcing row/column limits before ML processing."""
    try:
        file.file.seek(0)
        header = pd.read_csv(file.file, nrows=0)
    except Exception as exc:
        raise HTTPException(400, "Could not parse CSV header.") from exc

    if len(header.columns) == 0:
        raise HTTPException(400, "CSV does not contain any columns.")
    if len(header.columns) > MAX_COLUMNS:
        raise HTTPException(
            400,
            f"CSV has {len(header.columns):,} columns. Maximum allowed is {MAX_COLUMNS:,}.",
        )

    try:
        file.file.seek(0)
        df = pd.read_csv(file.file, nrows=max_rows + 1, low_memory=False)
    except Exception as exc:
        raise HTTPException(400, "Could not parse CSV data.") from exc

    if len(df) > max_rows:
        raise HTTPException(
            400,
            f"Dataset has more than {max_rows:,} rows. Maximum allowed is {max_rows:,}.",
        )
    return df


def _clean_raw(df: pd.DataFrame, require_label: bool) -> pd.DataFrame:
    """Dataset-agnostic cleaning for labeled tabular anomaly-detection CSVs."""
    df = df.drop_duplicates().copy()
    df.columns = [str(c).strip() for c in df.columns]

    if require_label and "label" not in df.columns:
        raise HTTPException(
            400,
            "Training CSV must contain a 'label' column (0=normal, 1=attack).",
        )

    # Remove common row/network identifiers when present.
    identifiers = [
        c
        for c in [
            "ts",
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_ip_addr",
            "dst_ip_addr",
        ]
        if c in df.columns
    ]
    df = df.drop(columns=identifiers, errors="ignore")

    df = df.replace(["-", "?", "NA", "N/A", "null", "NULL", ""], np.nan)
    return df


def _estimate_encoded_features(
    X_train: pd.DataFrame,
    categorical: list[str],
    numeric: list[str],
) -> int:
    encoded = len(numeric)
    for column in categorical:
        # dropna=False counts missing as a potential imputed/category state conservatively.
        encoded += int(X_train[column].nunique(dropna=False))
        if encoded > MAX_ENCODED_FEATURES:
            break
    return encoded


def _build_model(df: pd.DataFrame, model_type: str):
    y = pd.to_numeric(df["label"], errors="coerce")
    valid = y.isin([0, 1])
    df = df.loc[valid].copy()
    y = y.loc[valid].astype(int)

    if len(df) < 20 or y.nunique() < 2:
        raise HTTPException(
            400,
            "Training data must contain at least 20 valid rows and both label classes 0 and 1.",
        )

    # Use attack type for stratification when it is sufficiently populated; otherwise use label.
    stratify = y
    if "type" in df.columns and df["type"].nunique(dropna=True) > 1:
        counts = df["type"].value_counts(dropna=False)
        if len(counts) > 1 and int(counts.min()) >= 2:
            stratify = df["type"]

    X = df.drop(columns=[c for c in ["label", "type"] if c in df.columns])
    if not X.shape[1]:
        raise HTTPException(400, "No usable feature columns were found after removing label/type.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=stratify,
    )

    categorical = X_train.select_dtypes(
        include=["object", "category", "bool"]
    ).columns.tolist()
    numeric = [c for c in X_train.columns if c not in categorical]

    estimated_encoded = _estimate_encoded_features(X_train, categorical, numeric)
    if estimated_encoded > MAX_ENCODED_FEATURES:
        raise HTTPException(
            400,
            "Dataset would expand to too many encoded features "
            f"(estimated > {MAX_ENCODED_FEATURES:,}). "
            "Reduce high-cardinality categorical columns before training.",
        )

    categorical_pipe = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="most_frequent")),
            (
                "onehot",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=True,
                ),
            ),
        ]
    )

    numeric_pipe = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
        ]
    )

    transformers = []
    if categorical:
        transformers.append(("cat", categorical_pipe, categorical))
    if numeric:
        transformers.append(("num", numeric_pipe, numeric))

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")

    if model_type == "xgboost":
        classifier = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            n_jobs=1,
            eval_metric="logloss",
        )
    else:
        classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            # Keep server resource usage predictable.
            n_jobs=1,
        )

    pipe = Pipeline([("preprocess", preprocessor), ("model", classifier)])

    started = time.time()
    pipe.fit(X_train, y_train)
    elapsed = time.time() - started

    pred = pipe.predict(X_test)
    proba = pipe.predict_proba(X_test)[:, 1]
    cm = confusion_matrix(y_test, pred)

    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, proba)),
        "confusion_matrix": cm.tolist(),
        "train_time_sec": round(elapsed, 2),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "raw_feature_count": int(X.shape[1]),
        "estimated_encoded_features": int(estimated_encoded),
        "categorical_features": int(len(categorical)),
        "numeric_features": int(len(numeric)),
    }
    return pipe, metrics, list(X.columns)


@app.on_event("startup")
def startup_cleanup():
    _cleanup_expired_models()


@app.get("/api/health")
def health():
    _cleanup_expired_models()
    return {
        "status": "ok",
        "limits": {
            "max_upload_mb": round(MAX_UPLOAD_BYTES / (1024 * 1024)),
            "max_rows": MAX_TRAIN_ROWS,
            "max_columns": MAX_COLUMNS,
            "max_concurrent_trainings": MAX_CONCURRENT_TRAININGS,
            "training_timeout_seconds": TRAIN_TIMEOUT_SECONDS,
            "model_retention_seconds": MODEL_RETENTION_SECONDS,
        },
    }


@app.post("/api/train")
async def train(
    request: Request,
    file: UploadFile = File(...),
    model_type: Literal["random_forest", "xgboost"] = Form("random_forest"),
):
    _cleanup_expired_models()
    _check_rate_limit(
        f"train:{_client_ip(request)}",
        TRAIN_RATE_LIMIT,
        TRAIN_RATE_WINDOW_SECONDS,
    )
    _validate_csv_upload(file)
    df = _read_csv_limited(file, MAX_TRAIN_ROWS)

    original_rows = len(df)
    df = _clean_raw(df, require_label=True)
    cleaned_rows = len(df)

    # At most N expensive training jobs run simultaneously.
    try:
        await asyncio.wait_for(training_semaphore.acquire(), timeout=30)
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            503,
            "Training capacity is currently full. Please try again shortly.",
        ) from exc

    try:
        # ML libraries are synchronous, so run them off the event loop.
        # wait_for enforces the API timeout. n_jobs=1 + concurrency limit keeps CPU bounded.
        try:
            pipe, metrics, feature_columns = await asyncio.wait_for(
                asyncio.to_thread(_build_model, df, model_type),
                timeout=TRAIN_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise HTTPException(
                408,
                f"Training exceeded the {TRAIN_TIMEOUT_SECONDS // 60}-minute time limit.",
            ) from exc
    finally:
        training_semaphore.release()

    model_id = uuid.uuid4().hex[:12]
    artifact = {
        "pipeline": pipe,
        "model_type": model_type,
        "feature_columns": feature_columns,
        "created_at": time.time(),
    }

    model_path = MODEL_DIR / f"{model_id}.joblib"
    joblib.dump(artifact, model_path)

    return {
        "model_id": model_id,
        "model_type": model_type,
        "original_rows": original_rows,
        "cleaned_rows": cleaned_rows,
        "metrics": metrics,
        "expires_in_seconds": MODEL_RETENTION_SECONDS,
    }


@app.post("/api/predict")
async def predict(
    request: Request,
    model_id: str = Form(...),
    file: UploadFile = File(...),
):
    _cleanup_expired_models()
    _check_rate_limit(
        f"predict:{_client_ip(request)}",
        PREDICT_RATE_LIMIT,
        PREDICT_RATE_WINDOW_SECONDS,
    )
    _validate_model_id(model_id)
    _validate_csv_upload(file)

    path = MODEL_DIR / f"{model_id}.joblib"
    if not path.exists():
        raise HTTPException(
            404,
            "Model not found or it has expired. Train a model first.",
        )

    try:
        artifact = joblib.load(path)
    except Exception as exc:
        raise HTTPException(500, "Stored model could not be loaded.") from exc

    df = _read_csv_limited(file, MAX_PREDICT_ROWS)
    df = _clean_raw(df, require_label=False)

    X = df.drop(
        columns=[c for c in ["label", "type"] if c in df.columns],
        errors="ignore",
    )

    expected = artifact["feature_columns"]
    missing = [c for c in expected if c not in X.columns]
    if missing:
        raise HTTPException(
            400,
            "Prediction CSV is missing required columns: "
            + ", ".join(missing[:20])
            + ("..." if len(missing) > 20 else ""),
        )

    X = X[expected]
    pipe = artifact["pipeline"]

    try:
        probs = pipe.predict_proba(X)[:, 1]
    except Exception as exc:
        raise HTTPException(
            400,
            "Prediction failed. Check that the uploaded CSV is compatible with the training dataset.",
        ) from exc

    preds = (probs >= 0.5).astype(int)
    top_idx = np.argsort(-probs)[:10]

    return {
        "rows": int(len(X)),
        "normal": int((preds == 0).sum()),
        "anomalous": int((preds == 1).sum()),
        "anomaly_rate": float((preds == 1).mean()) if len(preds) else 0.0,
        "top": [
            {
                "row": int(i + 1),
                "attack_probability": float(probs[i]),
            }
            for i in top_idx
        ],
    }
