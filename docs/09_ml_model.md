# ML Model Details

## Model Types in Use

- **Supervised model:** `RandomForestClassifier` (`n_estimators=100`).
- **Unsupervised model:** `IsolationForest` (`n_estimators=100`, `contamination=0.01`).

## Feature Set

- Training pipeline uses numeric CIC-flow-derived features.
- Persisted feature schema is stored in `training_pipeline/models/artifacts/feature_names.pkl`.
- Current training metadata reports `feature_count: 79` in `metrics.json`.

## Training Process

Defined in `nal/training_pipeline/train.py`:

1. Recursively load CSVs from processed flow directories.
2. Clean data (`clean_data`) by removing NaN/Inf rows.
3. Drop non-predictive ID/time/address fields.
4. Fit scaler and label encoder.
5. Split data (80/20, stratified if labels exist).
6. Train RF on labeled split.
7. Train IF primarily on BENIGN class (if available), else on all training rows.
8. Save model and preprocessing artifacts.

## Inference Logic

Implemented in `decision_service.py`:

- Standardized feature alignment -> scaling -> RF + IF inference.
- IF score transformation: `anomaly_score = clip(0.5 - decision_function(), 0, 1)`.
- If RF predicts BENIGN but IF marks anomaly, rule-based threat inference is applied.

## Risk Scoring

- BENIGN + anomaly: `risk = anomaly_score * 0.6`
- Threat from supervised path: `risk = 0.7 * confidence + 0.3 * anomaly_score`
- Threat when supervised artifacts absent: pseudo-confidence formula + anomaly contribution + offset.

Risk levels:

- `Critical` if `risk > 0.8`
- `High` if `risk > 0.6`
- `Medium` if `risk > 0.3`
- else `Low`

## Threat Label Inference (Unsupervised Override)

When anomaly is detected on BENIGN prediction, `infer_anomaly_threat_type` uses behavior patterns:

- packet/rate bursts -> DDoS/Bot,
- probe-like sparse packets -> PortScan,
- service-port attack patterns -> Brute Force,
- web-port payload patterns -> Web Attack,
- special TLS shape -> Heartbleed,
- uncommon-port movement patterns -> Infiltration.

## Current Metrics State

- `training_pipeline/models/metrics.json` exists but currently contains empty `models` object in this repository snapshot.
- Backend falls back to runtime-only metrics for dashboard reporting if detailed model metrics are unavailable.

## Limitations

- Performance tracking is only as good as available `metrics.json`; current file lacks model metric blocks.
- Training quality depends on dataset curation and label consistency.
- Rule-based unsupervised label inference is heuristic and may over/under-classify in edge traffic patterns.
- Model reload behavior is startup-driven; retraining typically requires backend restart for deterministic artifact refresh.
