import React, { useState, useRef, useCallback, useEffect } from "react";
import * as tf from "@tensorflow/tfjs";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Legend, Area, AreaChart, ReferenceLine,
} from "recharts";
import Papa from "papaparse";
import sr from "./locales/sr.json";
import en from "./locales/en.json";
import DATA from "./utils/data.json";


const MODEL_STORAGE_KEY = "indexeddb://ton-iot-anomaly-model-v1";
const NORM_STORAGE_KEY = "ton-iot-anomaly-norm-stats-v1";
const MODEL_META_KEY = "ton-iot-anomaly-meta-v1";

const LANGS = { sr, en };

function computeNormStats(X) {
  const n = X.length, d = X[0].length;
  const mean = new Array(d).fill(0);
  const std = new Array(d).fill(0);
  for (let j = 0; j < d; j++) {
    let s = 0;
    for (let i = 0; i < n; i++) s += X[i][j];
    mean[j] = s / n;
  }
  for (let j = 0; j < d; j++) {
    let s = 0;
    for (let i = 0; i < n; i++) s += (X[i][j] - mean[j]) ** 2;
    std[j] = Math.sqrt(s / n) || 1;
  }
  return { mean, std };
}
function normalize(X, mean, std) {
  return X.map((row) => row.map((v, j) => (v - mean[j]) / std[j]));
}

// Обележја која МОРАЈУ бити присутна као сирове нумеричке колоне (не могу се извести)
// Мапа синонима назива колона - препознаје конвенцију именовања коју користи Zeek
// (алат на коме је заснован и ToN-IoT скуп података), као и уобичајене варијанте
// (camelCase, размаком одвојено, "id.resp_p" стил из Zeek conn.log-a итд).
// Ово НЕ покрива сваки могући формат мрежних токова (нпр. NetFlow/IPFIX/CICFlowMeter
// имају потпуно другачију структуру поља) - фокус је на Zeek-заснованим извозима,
// који су најчешћи у IoT/IDS истраживачком контексту.
const COLUMN_ALIASES = {
  dst_port: ["dst_port", "dstport", "dest_port", "destination_port", "id.resp_p", "resp_p"],
  proto: ["proto", "protocol", "transport_protocol"],
  service: ["service", "app_proto", "application_protocol"],
  conn_state: ["conn_state", "connection_state", "state"],
  src_bytes: ["src_bytes", "orig_bytes", "source_bytes"],
  dst_bytes: ["dst_bytes", "resp_bytes", "destination_bytes"],
  src_ip_bytes: ["src_ip_bytes", "orig_ip_bytes", "source_ip_bytes"],
  dst_ip_bytes: ["dst_ip_bytes", "resp_ip_bytes", "destination_ip_bytes"],
  src_pkts: ["src_pkts", "orig_pkts", "source_packets"],
  dst_pkts: ["dst_pkts", "resp_pkts", "destination_packets"],
  dns_query: ["dns_query", "query", "dns_name"],
  dns_rejected: ["dns_rejected", "rejected"],
  dns_RD: ["dns_RD", "dns_rd", "recursion_desired"],
};

// Нормализује имена колона у улазном реду - препознаје варијанте без обзира на
// велика/мала слова, размаке или тачке, и мапира их на канонски назив коришћен у моделу.
function normalizeColumnNames(row) {
  const normalized = {};
  const lookup = {};
  for (const [canonical, aliases] of Object.entries(COLUMN_ALIASES)) {
    for (const alias of aliases) {
      lookup[alias.toLowerCase().replace(/[\s.]+/g, "_")] = canonical;
    }
  }
  for (const [key, value] of Object.entries(row)) {
    const normKey = key.trim().toLowerCase().replace(/[\s.]+/g, "_");
    const canonical = lookup[normKey];
    normalized[canonical || key] = value;
  }
  return normalized;
}

const REQUIRED_NUMERIC_COLS = ["dst_port", "src_ip_bytes", "src_pkts", "dst_ip_bytes", "dst_pkts", "src_bytes"];

// Изводи вредност обележја из реда - прихвата или већ енкодирано обележје (нпр. proto_tcp=1)
// или сирове колоне уобичајене у мрежним логовима (нпр. proto="tcp", service="dns", conn_state="REJ")
function deriveFeatureValue(row, feature) {
  if (feature in row && row[feature] !== null && row[feature] !== undefined && row[feature] !== "") {
    return Number(row[feature]) || 0;
  }
  const proto = String(row.proto ?? "").toLowerCase();
  const service = String(row.service ?? "").toLowerCase();
  const connState = String(row.conn_state ?? "").toUpperCase();
  const dnsRejected = String(row.dns_rejected ?? "").toUpperCase();
  const dnsRD = String(row.dns_RD ?? "").toUpperCase();
  switch (feature) {
    case "proto_tcp": return proto === "tcp" ? 1 : 0;
    case "proto_udp": return proto === "udp" ? 1 : 0;
    case "conn_state_REJ": return connState === "REJ" ? 1 : 0;
    case "conn_state_OTH": return connState === "OTH" ? 1 : 0;
    case "service_dns": return service === "dns" ? 1 : 0;
    case "has_dns_query": return row.dns_query && row.dns_query !== "-" ? 1 : 0;
    case "dns_rejected_F": return dnsRejected === "F" || dnsRejected === "FALSE" || dnsRejected === "0" ? 1 : 0;
    case "dns_RD_F": return dnsRD === "F" || dnsRD === "FALSE" || dnsRD === "0" ? 1 : 0;
    default: return 0;
  }
}

function downloadBlob(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function buildTemplateCsv() {
  const header = "dst_port,src_ip_bytes,src_pkts,proto,dst_ip_bytes,dst_pkts,conn_state,src_bytes,service,dns_query";
  const rows = [
    "53,120,2,udp,180,2,SF,60,dns,example.com",
    "80,540,6,tcp,890,7,SF,320,-,-",
    "445,0,3,tcp,0,0,REJ,0,-,-",
    "22,1200,14,tcp,3400,18,SF,2100,-,-",
  ];
  return [header, ...rows].join("\n");
}

function computeMetrics(yTrue, yPred) {
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (let i = 0; i < yTrue.length; i++) {
    if (yTrue[i] === 1 && yPred[i] === 1) tp++;
    else if (yTrue[i] === 0 && yPred[i] === 0) tn++;
    else if (yTrue[i] === 0 && yPred[i] === 1) fp++;
    else fn++;
  }
  const acc = (tp + tn) / yTrue.length;
  const prec = tp + fp === 0 ? 0 : tp / (tp + fp);
  const rec = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = prec + rec === 0 ? 0 : (2 * prec * rec) / (prec + rec);
  return { tp, tn, fp, fn, acc, prec, rec, f1 };
}

// Рачуна ROC криву (TPR у функцији FPR) над низом прагова одлуке, и AUC
// применом трапезног правила интеграције - у складу са дефиницијом из поглавља 4.4.
function computeROC(yTrue, probs) {
  const nPos = yTrue.reduce((s, v) => s + v, 0);
  const nNeg = yTrue.length - nPos;
  const thresholds = Array.from({ length: 51 }, (_, i) => 1 - i / 50);
  const points = thresholds.map((thr) => {
    let tp = 0, fp = 0;
    for (let i = 0; i < yTrue.length; i++) {
      const pred = probs[i] >= thr ? 1 : 0;
      if (pred === 1 && yTrue[i] === 1) tp++;
      else if (pred === 1 && yTrue[i] === 0) fp++;
    }
    return {
      threshold: thr,
      tpr: nPos === 0 ? 0 : tp / nPos,
      fpr: nNeg === 0 ? 0 : fp / nNeg,
    };
  });
  points.sort((a, b) => a.fpr - b.fpr);
  let auc = 0;
  for (let i = 1; i < points.length; i++) {
    const dx = points[i].fpr - points[i - 1].fpr;
    const avgY = (points[i].tpr + points[i - 1].tpr) / 2;
    auc += dx * avgY;
  }
  return { points, auc };
}

export default function IoTAnomalyML() {
  const [lang, setLang] = useState(() => localStorage.getItem("ton-iot-lang") || "sr");
  const tr = LANGS[lang];

  const switchLang = useCallback((l) => {
    setLang(l);
    localStorage.setItem("ton-iot-lang", l);
  }, []);

  const [theme, setTheme] = useState(() => localStorage.getItem("ton-iot-theme") || "dark");
  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === "dark" ? "light" : "dark";
      localStorage.setItem("ton-iot-theme", next);
      return next;
    });
  }, []);
  const chartColors = theme === "dark"
    ? { grid: "#1e293b", axis: "#64748b", tooltipBg: "#0f172a", tooltipBorder: "#334155" }
    : { grid: "#e2e8f0", axis: "#64748b", tooltipBg: "#ffffff", tooltipBorder: "#cbd5e1" };

  const [phase, setPhase] = useState("idle");
  const [log, setLog] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [roc, setRoc] = useState(null);
  const [sampleIdx, setSampleIdx] = useState(null);
  const [livePred, setLivePred] = useState(null);
  const [loadedFromCache, setLoadedFromCache] = useState(false);
  const [checkingCache, setCheckingCache] = useState(true);
  const [importance, setImportance] = useState(null);
  const [importanceRunning, setImportanceRunning] = useState(false);
  const [csvResults, setCsvResults] = useState(null);
  const [csvPreview, setCsvPreview] = useState(null);
  const [csvError, setCsvError] = useState(null);
  const [csvProcessing, setCsvProcessing] = useState(false);
  const [csvFileName, setCsvFileName] = useState(null);

  const modelRef = useRef(null);
  const csvSectionRef = useRef(null);
  const normRef = useRef(null);
  const testPredsRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const normJson = localStorage.getItem(NORM_STORAGE_KEY);
        if (!normJson) {
          setCheckingCache(false);
          return;
        }
        const loaded = await tf.loadLayersModel(MODEL_STORAGE_KEY);
        if (cancelled) return;
        loaded.compile({ optimizer: tf.train.adam(0.01), loss: "binaryCrossentropy", metrics: ["accuracy"] });
        modelRef.current = loaded;
        normRef.current = JSON.parse(normJson);

        const Xte = normalize(DATA.X_test, normRef.current.mean, normRef.current.std);
        const t = tf.tensor2d(Xte);
        const pred = loaded.predict(t);
        const probs = Array.from(await pred.data());
        const preds = probs.map((p) => (p >= 0.5 ? 1 : 0));
        const m = computeMetrics(DATA.y_test, preds);
        const r = computeROC(DATA.y_test, probs);
        t.dispose(); pred.dispose();

        if (!cancelled) {
          setMetrics(m);
          setRoc(r);
          setLoadedFromCache(true);
          setPhase("done");
        }
      } catch (e) {
        // nema sačuvanog modela ili je oštećen - normalan tok, korisnik trenira ispočetka
      } finally {
        if (!cancelled) setCheckingCache(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const clearCachedModel = useCallback(async () => {
    try {
      await tf.io.removeModel(MODEL_STORAGE_KEY);
    } catch (e) {}
    localStorage.removeItem(NORM_STORAGE_KEY);
    localStorage.removeItem(MODEL_META_KEY);
    modelRef.current = null;
    normRef.current = null;
    setLoadedFromCache(false);
    setPhase("idle");
    setMetrics(null);
    setRoc(null);
    setLog([]);
    setLivePred(null);
  }, []);

  const startTraining = useCallback(async () => {
    setPhase("training");
    setLog([]);
    setMetrics(null);
    setRoc(null);
    setImportance(null);

    const { mean, std } = computeNormStats(DATA.X_train);
    normRef.current = { mean, std };
    const Xtr = normalize(DATA.X_train, mean, std);
    const Xte = normalize(DATA.X_test, mean, std);

    const xTrainT = tf.tensor2d(Xtr);
    const yTrainT = tf.tensor2d(DATA.y_train.map((v) => [v]));
    const xTestT = tf.tensor2d(Xte);
    const yTestT = tf.tensor2d(DATA.y_test.map((v) => [v]));

    const model = tf.sequential();
    model.add(tf.layers.dense({ units: 16, activation: "relu", inputShape: [DATA.features.length] }));
    model.add(tf.layers.dense({ units: 8, activation: "relu" }));
    model.add(tf.layers.dense({ units: 1, activation: "sigmoid" }));
    model.compile({ optimizer: tf.train.adam(0.01), loss: "binaryCrossentropy", metrics: ["accuracy"] });
    modelRef.current = model;

    await model.fit(xTrainT, yTrainT, {
      epochs: 25,
      batchSize: 32,
      validationData: [xTestT, yTestT],
      callbacks: {
        onEpochEnd: async (epoch, logs) => {
          setLog((prev) => [
            ...prev,
            {
              epoch: epoch + 1,
              loss: Number(logs.loss.toFixed(4)),
              acc: Number((logs.acc ?? logs.accuracy).toFixed(4)),
              valLoss: Number(logs.val_loss.toFixed(4)),
              valAcc: Number((logs.val_acc ?? logs.val_accuracy).toFixed(4)),
            },
          ]);
          await tf.nextFrame();
        },
      },
    });

    const predTensor = model.predict(xTestT);
    const probs = Array.from(await predTensor.data());
    const preds = probs.map((p) => (p >= 0.5 ? 1 : 0));
    testPredsRef.current = probs;
    const m = computeMetrics(DATA.y_test, preds);
    setMetrics(m);
    setRoc(computeROC(DATA.y_test, probs));
    setPhase("done");
    setLoadedFromCache(false);

    try {
      await model.save(MODEL_STORAGE_KEY);
      localStorage.setItem(NORM_STORAGE_KEY, JSON.stringify({ mean, std }));
      localStorage.setItem(MODEL_META_KEY, JSON.stringify({ trainedAt: new Date().toISOString(), acc: m.acc }));
    } catch (e) {
      // čuvanje u IndexedDB nije uspelo (нпр. приватни режим прегледача) - модел и даље ради у меморији
    }

    xTrainT.dispose(); yTrainT.dispose(); xTestT.dispose(); yTestT.dispose(); predTensor.dispose();
  }, []);

  // Аутоматски покреће тренирање чим се утврди да нема сачуваног модела у прегледачу -
  // корисник не мора да кликће дугме да би добио резултате.
  useEffect(() => {
    if (!checkingCache && phase === "idle") {
      startTraining();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [checkingCache]);

  const testRandomSample = useCallback(() => {
    if (!modelRef.current || !normRef.current) return;
    const idx = Math.floor(Math.random() * DATA.X_test.length);
    setSampleIdx(idx);
    const { mean, std } = normRef.current;
    const row = normalize([DATA.X_test[idx]], mean, std);
    const t = tf.tensor2d(row);
    const pred = modelRef.current.predict(t);
    pred.data().then((d) => {
      setLivePred({ prob: d[0], actual: DATA.y_test[idx] });
      t.dispose(); pred.dispose();
    });
  }, []);

  const computeImportance = useCallback(async () => {
    if (!modelRef.current || !normRef.current || !metrics) return;
    setImportanceRunning(true);
    const { mean, std } = normRef.current;
    const baseXte = normalize(DATA.X_test, mean, std);
    const baseAcc = metrics.acc;
    const results = [];
    for (let j = 0; j < DATA.features.length; j++) {
      const shuffled = baseXte.map((r) => [...r]);
      const col = shuffled.map((r) => r[j]);
      for (let i = col.length - 1; i > 0; i--) {
        const k = Math.floor(Math.random() * (i + 1));
        [col[i], col[k]] = [col[k], col[i]];
      }
      shuffled.forEach((r, i) => (r[j] = col[i]));
      const t = tf.tensor2d(shuffled);
      const pred = modelRef.current.predict(t);
      const probs = Array.from(await pred.data());
      const preds = probs.map((p) => (p >= 0.5 ? 1 : 0));
      const m = computeMetrics(DATA.y_test, preds);
      results.push({ feature: tr.features[DATA.features[j]] || DATA.features[j], drop: Math.max(0, baseAcc - m.acc) });
      t.dispose(); pred.dispose();
      await tf.nextFrame();
    }
    results.sort((a, b) => b.drop - a.drop);
    setImportance(results);
    setImportanceRunning(false);
  }, [metrics, lang]);

  const handleCsvUpload = useCallback((e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (!modelRef.current || !normRef.current) {
      setCsvError(tr.csv.errors.noModel);
      return;
    }
    setCsvError(null);
    setCsvResults(null);
    setCsvPreview(null);
    setCsvProcessing(true);
    setCsvFileName(file.name);

    Papa.parse(file, {
      header: true,
      dynamicTyping: true,
      skipEmptyLines: true,
      complete: (parsed) => {
        try {
          const rawRows = parsed.data;
          if (!rawRows.length) {
            setCsvError(tr.csv.errors.empty);
            setCsvProcessing(false);
            return;
          }
          const rows = rawRows.map(normalizeColumnNames);
          const missing = REQUIRED_NUMERIC_COLS.filter((f) => !(f in rows[0]));
          if (missing.length > 0) {
            setCsvError(tr.csv.errors.missingCols + " " + missing.join(", "));
            setCsvProcessing(false);
            return;
          }
          const X = rows.map((r) => DATA.features.map((f) => deriveFeatureValue(r, f)));

          // Преглед - прве 3 инстанце, ради визуелне провере да ли је препознавање колона исправно
          const previewRows = rows.slice(0, 3).map((r, idx) => ({
            index: idx + 1,
            values: DATA.features.map((f) => ({ feature: f, value: X[idx][DATA.features.indexOf(f)] })),
          }));
          setCsvPreview(previewRows);

          const { mean, std } = normRef.current;
          const Xn = normalize(X, mean, std);
          const t = tf.tensor2d(Xn);
          const pred = modelRef.current.predict(t);
          pred.data().then((probsData) => {
            const probs = Array.from(probsData);
            const anomalous = probs.filter((p) => p >= 0.5).length;
            const all = probs.map((p, i) => ({ i, p, label: p >= 0.5 ? 1 : 0 }));
            const ranked = [...all].sort((a, b) => b.p - a.p).slice(0, 10);
            setCsvResults({
              total: rows.length,
              normal: rows.length - anomalous,
              anomalous,
              rate: ((anomalous / rows.length) * 100).toFixed(1),
              top: ranked,
              all,
            });
            setCsvProcessing(false);
            t.dispose();
            pred.dispose();
          });
        } catch (err) {
          setCsvError(tr.csv.errors.parse + " " + err.message);
          setCsvProcessing(false);
        }
      },
      error: (err) => {
        setCsvError(tr.csv.errors.read + " " + err.message);
        setCsvProcessing(false);
      },
    });
  }, [lang]);

  const downloadResultsCsv = useCallback(() => {
    if (!csvResults?.all) return;
    const header = "row_index,anomaly_probability,predicted_label";
    const lines = csvResults.all.map(
      (r) => `${r.i + 1},${r.p.toFixed(4)},${r.label === 1 ? "anomalous" : "normal"}`
    );
    downloadBlob([header, ...lines].join("\n"), "anomaly_detection_results.csv", "text/csv");
  }, [csvResults]);

  const downloadTemplate = useCallback(() => {
    downloadBlob(buildTemplateCsv(), "traffic_template.csv", "text/csv");
  }, []);

  const scrollToUpload = useCallback(() => {
    csvSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  return (
    <div className={(theme === "dark" ? "dark " : "") + "min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans transition-colors"}>
      <div className="max-w-5xl mx-auto px-4 sm:px-6 py-6 sm:py-10">
        <div className="flex items-center justify-between flex-wrap gap-3 mb-2">
          <div className="flex items-center gap-2 text-xs font-mono tracking-widest uppercase text-teal-600 dark:text-teal-400">
            <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shadow-[0_0_8px_rgba(45,217,190,0.8)]" />
            {tr.eyebrow}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={toggleTheme}
              aria-label="Toggle theme"
              className="w-7 h-7 rounded-full border border-slate-300 dark:border-slate-700 flex items-center justify-center text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 transition-colors"
            >
              {theme === "dark" ? (
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <circle cx="12" cy="12" r="4" />
                  <path strokeLinecap="round" d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
                </svg>
              ) : (
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
                </svg>
              )}
            </button>
            <div className="flex items-center gap-1 text-xs font-mono border border-slate-300 dark:border-slate-700 rounded-full p-0.5">
              <button
                onClick={() => switchLang("sr")}
                className={"px-2.5 py-1 rounded-full transition-colors " + (lang === "sr" ? "bg-teal-500 text-slate-950" : "text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200")}
              >
                SR
              </button>
              <button
                onClick={() => switchLang("en")}
                className={"px-2.5 py-1 rounded-full transition-colors " + (lang === "en" ? "bg-teal-500 text-slate-950" : "text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200")}
              >
                EN
              </button>
            </div>
          </div>
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight mb-2">
          {tr.title}
        </h1>
        <p className="text-slate-600 dark:text-slate-400 text-sm max-w-2xl mb-4">
          {tr.subtitle}
        </p>
        <button
          onClick={scrollToUpload}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 font-medium text-sm transition-colors mb-8"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 16V4m0 0L8 8m4-4l4 4M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" />
          </svg>
          {tr.ctaUpload}
        </button>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden mb-4">
          <Stat label={tr.stats.train} value={DATA.X_train.length.toLocaleString(lang === "sr" ? "sr-RS" : "en-US")} />
          <Stat label={tr.stats.test} value={DATA.X_test.length.toLocaleString(lang === "sr" ? "sr-RS" : "en-US")} />
          <Stat label={tr.stats.features} value={DATA.features.length} />
          <Stat label={tr.stats.arch} value="14→16→8→1" small />
        </div>

        {checkingCache && (
          <div className="flex items-center gap-2 text-xs font-mono text-slate-500 mb-8">
            <Spinner className="w-3.5 h-3.5" />
            {tr.cache.checking}
          </div>
        )}
        {!checkingCache && loadedFromCache && (
          <div className="flex items-center justify-between flex-wrap gap-2 text-xs font-mono bg-teal-500/10 border border-teal-500/20 rounded-lg px-3 py-2 mb-8">
            <span className="text-teal-600 dark:text-teal-400">{tr.cache.loaded}</span>
            <button onClick={clearCachedModel} className="text-slate-600 dark:text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 underline">
              {tr.cache.clear}
            </button>
          </div>
        )}

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-6 mb-8">
          <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
            <div>
              <h2 className="text-lg font-medium flex items-center">
                {tr.training.title}
                <InfoTip text={tr.training.tooltip} ariaLabel={tr.infoTipLabel} />
              </h2>
              <p className="text-slate-500 text-xs font-mono mt-0.5">
                {tr.training.archDesc}
              </p>
            </div>
            <button
              onClick={startTraining}
              disabled={phase === "training"}
              className="px-4 py-2 rounded-lg bg-teal-500 hover:bg-teal-400 disabled:bg-slate-300 dark:disabled:bg-slate-700 disabled:text-slate-500 text-slate-950 font-medium text-sm transition-colors inline-flex items-center gap-2"
            >
              {phase === "training" && <Spinner className="w-4 h-4 text-slate-950" />}
              {phase === "training" ? tr.training.btnRunning : phase === "done" ? tr.training.btnDone : tr.training.btnIdle}
            </button>
          </div>

          {log.length > 0 && (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={log}>
                  <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" />
                  <XAxis dataKey="epoch" stroke={chartColors.axis} fontSize={11} label={{ value: tr.chart.epoch, position: "insideBottom", offset: -3, fill: chartColors.axis, fontSize: 11 }} />
                  <YAxis stroke={chartColors.axis} fontSize={11} domain={[0, 1]} />
                  <Tooltip contentStyle={{ background: chartColors.tooltipBg, border: "1px solid " + chartColors.tooltipBorder, fontSize: 12, color: theme === "dark" ? "#e2e8f0" : "#0f172a" }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line type="monotone" dataKey="acc" name={tr.chart.trainAcc} stroke="#2dd9be" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="valAcc" name={tr.chart.valAcc} stroke="#4c8dff" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="loss" name={tr.chart.trainLoss} stroke="#f1555f" strokeWidth={1.5} strokeDasharray="4 3" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
          {log.length === 0 && (
            <div className="h-64 flex items-center justify-center text-slate-600 text-sm font-mono text-center px-4">
              {tr.training.placeholder}
            </div>
          )}
        </div>

        {metrics && (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-6 mb-8">
            <h2 className="text-lg font-medium mb-4">{tr.results.title}</h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
              <Metric label={tr.results.accuracy} value={metrics.acc} />
              <Metric label={tr.results.precision} value={metrics.prec} />
              <Metric label={tr.results.recall} value={metrics.rec} />
              <Metric label={tr.results.f1} value={metrics.f1} highlight />
            </div>
            <div className="grid grid-cols-2 gap-2 max-w-sm">
              <CmCell label="TN" value={metrics.tn} tone="teal" />
              <CmCell label="FP" value={metrics.fp} tone="coral" />
              <CmCell label="FN" value={metrics.fn} tone="coral" />
              <CmCell label="TP" value={metrics.tp} tone="blue" />
            </div>
          </div>
        )}

        {roc && (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-6 mb-8">
            <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
              <h2 className="text-lg font-medium flex items-center">
                {tr.roc.title}
                <InfoTip text={tr.roc.tooltip} ariaLabel={tr.infoTipLabel} />
              </h2>
              <div className="text-sm font-mono">
                <span className="text-slate-500">AUC = </span>
                <span className="text-teal-600 dark:text-teal-400 font-semibold">{roc.auc.toFixed(4)}</span>
              </div>
            </div>
            <div className="h-64 mt-3">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={roc.points} margin={{ left: 0, right: 10 }}>
                  <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" />
                  <XAxis
                    dataKey="fpr" type="number" domain={[0, 1]} stroke={chartColors.axis} fontSize={11}
                    label={{ value: tr.roc.fpr, position: "insideBottom", offset: -3, fill: chartColors.axis, fontSize: 11 }}
                  />
                  <YAxis
                    domain={[0, 1]} stroke={chartColors.axis} fontSize={11}
                    label={{ value: tr.roc.tpr, angle: -90, position: "insideLeft", fill: chartColors.axis, fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{ background: chartColors.tooltipBg, border: "1px solid " + chartColors.tooltipBorder, fontSize: 12, color: theme === "dark" ? "#e2e8f0" : "#0f172a" }}
                    formatter={(v, name) => [Number(v).toFixed(3), name]}
                  />
                  <ReferenceLine segment={[{ x: 0, y: 0 }, { x: 1, y: 1 }]} stroke={chartColors.axis} strokeDasharray="4 4" />
                  <Area type="monotone" dataKey="tpr" name="TPR" stroke="#2dd9be" fill="#2dd9be" fillOpacity={0.15} strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {phase === "done" && (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-6 mb-8">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
              <h2 className="text-lg font-medium flex items-center">
                {tr.livePred.title}
                <InfoTip text={tr.livePred.tooltip} ariaLabel={tr.infoTipLabel} />
              </h2>
              <button
                onClick={testRandomSample}
                className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-sm text-teal-600 dark:text-teal-400 font-mono"
              >
                {tr.livePred.btnTest}
              </button>
            </div>
            {livePred ? (
              <div className="flex items-center gap-6 flex-wrap">
                <div>
                  <div className="text-xs text-slate-500 font-mono uppercase">{tr.livePred.modelPredicts}</div>
                  <div className={"text-2xl font-semibold " + (livePred.prob >= 0.5 ? "text-rose-600 dark:text-rose-400" : "text-teal-600 dark:text-teal-400")}>
                    {(livePred.prob * 100).toFixed(1)}% {tr.livePred.probAttack}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-slate-500 font-mono uppercase">{tr.livePred.actualLabel}</div>
                  <div className={"text-2xl font-semibold " + (livePred.actual === 1 ? "text-rose-600 dark:text-rose-400" : "text-teal-600 dark:text-teal-400")}>
                    {livePred.actual === 1 ? tr.livePred.anomalous : tr.livePred.normal}
                  </div>
                </div>
                <div className="text-xs font-mono px-3 py-1.5 rounded-full "
                     style={{ background: (livePred.prob >= 0.5) === (livePred.actual === 1) ? "rgba(45,217,190,0.12)" : "rgba(241,85,95,0.12)",
                       color: (livePred.prob >= 0.5) === (livePred.actual === 1) ? "#2dd9be" : "#f1555f" }}>
                  {(livePred.prob >= 0.5) === (livePred.actual === 1) ? tr.livePred.correct : tr.livePred.incorrect}
                </div>
              </div>
            ) : (
              <p className="text-slate-500 text-sm font-mono">{tr.livePred.placeholder}</p>
            )}
          </div>
        )}

        {phase === "done" && (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-6 mb-8">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
              <div>
                <h2 className="text-lg font-medium flex items-center">
                  {tr.importance.title}
                  <InfoTip text={tr.importance.tooltip} ariaLabel={tr.infoTipLabel} />
                </h2>
                <p className="text-slate-500 text-xs font-mono mt-0.5">{tr.importance.desc}</p>
              </div>
              <button
                onClick={computeImportance}
                disabled={importanceRunning}
                className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:text-slate-600 text-sm text-teal-600 dark:text-teal-400 font-mono inline-flex items-center gap-2"
              >
                {importanceRunning && <Spinner className="w-3.5 h-3.5" />}
                {importanceRunning ? tr.importance.btnRunning : tr.importance.btnIdle}
              </button>
            </div>
            {importance && (
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={importance} layout="vertical" margin={{ left: 110 }}>
                    <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" horizontal={false} />
                    <XAxis type="number" stroke={chartColors.axis} fontSize={11} />
                    <YAxis type="category" dataKey="feature" stroke={chartColors.axis} fontSize={11} width={110} />
                    <Tooltip contentStyle={{ background: chartColors.tooltipBg, border: "1px solid " + chartColors.tooltipBorder, fontSize: 12, color: theme === "dark" ? "#e2e8f0" : "#0f172a" }} />
                    <Bar dataKey="drop" name={tr.importance.dropLabel} fill="#2dd9be" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}

        {phase === "done" && (
          <div ref={csvSectionRef} className="bg-white dark:bg-slate-900 border-2 border-teal-500/30 dark:border-teal-500/30 rounded-xl p-4 sm:p-6 mt-8 scroll-mt-4">
            <h2 className="text-xl font-semibold mb-1 flex items-center">
              {tr.csv.title}
              <InfoTip text={tr.csv.tooltip} ariaLabel={tr.infoTipLabel} />
            </h2>
            <p className="text-slate-600 dark:text-slate-400 text-sm mb-4">{tr.csv.intro}</p>

            <div className="text-xs text-amber-700 dark:text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2 mb-4 flex items-start gap-1.5">
              <svg className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
              <span>{tr.csv.disclaimer}</span>
            </div>

            <details className="mb-4 group">
              <summary className="cursor-pointer text-xs font-mono text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 select-none flex items-center gap-1.5">
                <svg className="w-3.5 h-3.5 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
                {tr.csv.formatDetails}
              </summary>
              <div className="mt-2 pl-5">
                <p className="text-slate-600 dark:text-slate-400 text-xs font-mono mb-1 break-words">
                  {tr.csv.requiredCols} {REQUIRED_NUMERIC_COLS.join(", ")}
                </p>
                <p className="text-slate-500 text-xs font-mono mb-1 break-words">
                  {tr.csv.optionalCols} proto, service, conn_state, dns_query
                </p>
                <p className="text-slate-500 text-xs break-words">{tr.csv.zeekNote}</p>
              </div>
            </details>

            <div className="flex flex-wrap items-center gap-2 mb-2">
              <label className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-dashed border-slate-300 dark:border-slate-700 hover:border-teal-500 hover:bg-slate-100 dark:hover:bg-slate-800/50 cursor-pointer text-sm text-slate-700 dark:text-slate-300 transition-colors">
                <svg className="w-4 h-4 text-teal-600 dark:text-teal-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 16V4m0 0L8 8m4-4l4 4M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" />
                </svg>
                {csvFileName ? csvFileName : tr.csv.chooseFile}
                <input type="file" accept=".csv" onChange={handleCsvUpload} className="hidden" />
              </label>
              <button
                onClick={downloadTemplate}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-mono text-slate-600 dark:text-slate-400"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v4h16V4M8 12h8M8 16h5" />
                </svg>
                {tr.csv.downloadTemplate}
              </button>
            </div>

            {csvProcessing && (
              <div className="mt-4 flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400 font-mono">
                <Spinner className="w-4 h-4 text-teal-600 dark:text-teal-400" />
                {tr.csv.processing}
              </div>
            )}

            {csvError && (
              <div className="mt-4 text-sm text-rose-600 dark:text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-lg px-3 py-2">
                {csvError}
              </div>
            )}

            {csvPreview && (
              <details className="mt-4 group">
                <summary className="cursor-pointer text-xs font-mono text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 select-none flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                  {tr.csv.previewTitle}
                </summary>
                <div className="mt-2 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  <table className="w-full text-[11px] font-mono">
                    <thead>
                    <tr className="bg-slate-100 dark:bg-slate-800">
                      <th className="px-2 py-1.5 text-left text-slate-500">#</th>
                      {DATA.features.map((f) => (
                        <th key={f} className="px-2 py-1.5 text-left text-slate-500 whitespace-nowrap">{f}</th>
                      ))}
                    </tr>
                    </thead>
                    <tbody>
                    {csvPreview.map((row) => (
                      <tr key={row.index} className="border-t border-slate-200 dark:border-slate-800">
                        <td className="px-2 py-1.5 text-slate-500">{row.index}</td>
                        {row.values.map((v) => (
                          <td key={v.feature} className="px-2 py-1.5 text-slate-700 dark:text-slate-300 whitespace-nowrap">{v.value}</td>
                        ))}
                      </tr>
                    ))}
                    </tbody>
                  </table>
                </div>
                <p className="text-[11px] text-slate-500 mt-1.5">{tr.csv.previewNote}</p>
              </details>
            )}

            {csvResults && (
              <div className="mt-5">
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-5">
                  <Metric2 label={tr.csv.analyzed} value={csvResults.total} lang={lang} />
                  <Metric2 label={tr.csv.normal} value={csvResults.normal} tone="teal" lang={lang} />
                  <Metric2 label={tr.csv.anomalous} value={csvResults.anomalous} tone="coral" lang={lang} />
                </div>
                <div className="text-xs font-mono text-slate-500 mb-1">
                  {tr.csv.anomalyRate} <span className="text-slate-700 dark:text-slate-300">{csvResults.rate}%</span>
                </div>
                <div className="h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden mb-5">
                  <div
                    className="h-full bg-gradient-to-r from-teal-400 to-rose-400"
                    style={{ width: Math.min(csvResults.rate, 100) + "%" }}
                  />
                </div>
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs font-mono text-slate-500 uppercase">{tr.csv.topRows}</div>
                  <button
                    onClick={downloadResultsCsv}
                    className="inline-flex items-center gap-1.5 text-xs font-mono text-teal-600 dark:text-teal-400 hover:underline"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v12m0 0l-4-4m4 4l4-4M4 20h16" />
                    </svg>
                    {tr.csv.downloadResults}
                  </button>
                </div>
                <div className="space-y-1">
                  {csvResults.top.map((r) => (
                    <div key={r.i} className="flex items-center justify-between text-xs font-mono bg-slate-100 dark:bg-slate-800/50 rounded-md px-3 py-1.5">
                      <span className="text-slate-600 dark:text-slate-400">{tr.csv.row} #{r.i + 1}</span>
                      <span
                        className={
                          "px-2 py-0.5 rounded-full " +
                          (r.p >= 0.5 ? "bg-rose-500/10 text-rose-600 dark:text-rose-400" : "bg-teal-500/10 text-teal-600 dark:text-teal-400")
                        }
                      >
                        {(r.p * 100).toFixed(1)}% {tr.csv.probAttack}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, small }) {
  return (
    <div className="bg-white dark:bg-slate-900 px-4 py-3">
      <div className="text-[11px] font-mono uppercase text-slate-500">{label}</div>
      <div className={"font-semibold mt-1 " + (small ? "text-sm text-slate-700 dark:text-slate-300" : "text-xl")}>{value}</div>
    </div>
  );
}
function Metric({ label, value, highlight }) {
  return (
    <div className="bg-slate-100 dark:bg-slate-800/60 rounded-lg px-3 py-2.5">
      <div className="text-[11px] font-mono uppercase text-slate-500">{label}</div>
      <div className={"text-xl font-semibold mt-0.5 " + (highlight ? "text-teal-600 dark:text-teal-400" : "text-slate-900 dark:text-slate-100")}>
        {(value * 100).toFixed(1)}%
      </div>
    </div>
  );
}
function Metric2({ label, value, tone, lang }) {
  const toneClass = tone === "teal" ? "text-teal-600 dark:text-teal-400" : tone === "coral" ? "text-rose-600 dark:text-rose-400" : "text-slate-900 dark:text-slate-100";
  return (
    <div className="bg-slate-100 dark:bg-slate-800/60 rounded-lg px-3 py-2.5">
      <div className="text-[11px] font-mono uppercase text-slate-500">{label}</div>
      <div className={"text-xl font-semibold mt-0.5 " + toneClass}>{value.toLocaleString(lang === "sr" ? "sr-RS" : "en-US")}</div>
    </div>
  );
}

function CmCell({ label, value, tone }) {
  const tones = {
    teal: "bg-teal-500/10 text-teal-600 dark:text-teal-400",
    coral: "bg-rose-500/10 text-rose-600 dark:text-rose-400",
    blue: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  };
  return (
    <div className={"rounded-lg px-3 py-3 text-center " + tones[tone]}>
      <div className="text-lg font-semibold">{value}</div>
      <div className="text-[10px] font-mono uppercase opacity-75 mt-0.5">{label}</div>
    </div>
  );
}

function Spinner({ className }) {
  return (
    <svg
      className={"animate-spin " + (className || "w-4 h-4")}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8v3a5 5 0 00-5 5H4z" />
    </svg>
  );
}

function InfoTip({ text, ariaLabel }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative inline-block ml-1.5 align-middle">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label={ariaLabel || "Info"}
        className="w-4 h-4 rounded-full bg-slate-300 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-[10px] leading-4 inline-flex items-center justify-center hover:bg-slate-400 dark:hover:bg-slate-600 transition-colors"
      >
        i
      </button>
      {open && (
        <span className="absolute z-20 left-1/2 -translate-x-1/2 bottom-6 w-56 text-xs bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 text-slate-700 dark:text-slate-300 shadow-xl leading-snug">
          {text}
        </span>
      )}
    </span>
  );
}