# Secure E-Voting System: ML Anomaly Detection

## Member 3 scope

This standalone module analyzes synthetic security-event session windows and creates alerts for human review. It never blocks, rejects, or invalidates a vote. Do not feed voter names, personal information, candidate information, or ballot contents to the ML pipeline.

It models patterns associated with brute-force login, token replay, bot traffic, and credential stuffing. The data is synthetic and is not real election or voter data.

## Requirements

- Python 3.11+ (verified here with Python 3.12)
- pandas, NumPy, scikit-learn, Flask, joblib, matplotlib
- The standalone core does not start a Flask API; integration is a separate task.

## Files

- `generate_dataset.py`: reproducibly creates 10,000 rows with NumPy seed 42.
- `dataset.csv`: generated synthetic session-window data (95% normal, 5% attacks).
- `preprocessing.py`: validates columns, stratifies a fixed-seed train/test split, and defines an imputer/scaler pipeline.
- `train_model.py`: fits preprocessing on training data only, trains Isolation Forest on normal training samples and a supervised Random Forest, then saves artifacts.
- `preprocessing_pipeline.pkl`: fitted imputer/scaler saved separately with joblib.
- `model.pkl`: both trained models and the fitted preprocessing pipeline.
- `evaluate.py`: evaluates both models against the same held-out rows and creates JSON metrics, plots, and a report.
- `evaluation_metrics.json`, `evaluation_report.md`: actual measured results and limitations.
- `feature_distributions.png`, `confusion_matrices.png`, `anomaly_score_histogram.png`, `pca_scatter.png`: generated evaluation figures.
- `detection.py`: validates a security-event record and returns a score, severity, and short review reason.
- `tests/test_ml.py`: standard-library unit tests for the dataset, preprocessing, model loading, and scoring.

## Run from the project root

Use the Windows Python launcher (`py`). Run in this order:

```powershell
py machine_learning/generate_dataset.py
py machine_learning/train_model.py
py machine_learning/evaluate.py
py -m unittest discover -s machine_learning/tests -v
```

To run scripts while already inside `machine_learning/`, use:

```powershell
py generate_dataset.py
py train_model.py
py evaluate.py
py -m unittest discover -s tests -v
```

The generator always uses seed `42`; running it twice with the same code produces byte-identical CSV output. Training and splitting use fixed random states for repeatable results.

## Model notes and safety

Isolation Forest is fit only on normal training examples. Its contamination setting is 0.05, near the simulated attack fraction. Random Forest provides a supervised comparison. Both are evaluated on the same stratified held-out test set. The anomaly score is a ranking signal, not a calibrated probability.

Metrics describe only the chosen synthetic generator and split. They do not establish real-world election security or performance. Every alert requires human review and must not affect vote acceptance.

## Flask security API (Member 3)

`security_api.py` provides a Flask Blueprint with these routes:

- `POST /api/security/score`: score a session window and store a new alert.
- `GET /api/security/alerts?limit=20`: return recent alerts (limit 1–100).
- `GET /api/security/summary`: return total alerts and severity/status counts.

All endpoints use this envelope:

```json
{"success": true, "data": {}, "error": null}
```

Errors use the same keys with `success: false`, `data: null`, and an `error` object containing a code and message.

### Score request and response example

Send only the eight permitted numerical features. Optional `simulated` should be `true` for a synthetic/demo request; it defaults to `false`. Unknown fields are rejected so personal details or election data cannot be stored.

```json
{
  "failed_logins": 4,
  "requests_per_minute": 75,
  "login_attempts": 7,
  "token_requests": 5,
  "distinct_accounts_per_ip": 2,
  "avg_gap_between_requests": 1.8,
  "session_duration": 3.2,
  "off_hours_flag": 1,
  "simulated": true
}
```

Successful scoring returns HTTP 201:

```json
{
  "success": true,
  "data": {
    "alert_id": 1,
    "anomaly_score": 0.82,
    "severity": "high",
    "reason": "Both models flag unusual security-event patterns.",
    "status": "new",
    "simulated": true,
    "human_review_only": true
  },
  "error": null
}
```

The score above is an illustrative response shape, not a measured result. Scores are ranking signals, not calibrated probabilities. Alerts never block, reject, or invalidate votes.

Alerts responses contain safe numeric feature values, alert metadata, and the `simulated` flag. The summary response has this shape:

```json
{
  "success": true,
  "data": {
    "total_alerts": 1,
    "severity_counts": {"low": 0, "medium": 0, "high": 1},
    "status_counts": {"new": 1},
    "human_review_only": true
  },
  "error": null
}
```

### Registering the Blueprint in Member 4's Flask app

After the team backend exists, Member 4 can register the Blueprint in its app factory. Point `DATABASE` at the team's existing SQLite file, then initialize the table in that same file:

```python
from security_api import create_security_blueprint, init_security_alerts_table

app.config["DATABASE"] = r"C:\path\to\the\existing_team_database.sqlite"
app.register_blueprint(create_security_blueprint())
init_security_alerts_table(app.config["DATABASE"])
```

Alternatively, configure `SECURITY_DATABASE`; that setting takes precedence over `DATABASE`. `init_security_alerts_table` and the API require an existing database file. Connections use SQLite read/write mode and will not silently create a separate database. If the existing application already has a SQLite connection strategy, Member 4 should adapt the connection helper in `security_api.py` to reuse it rather than create a parallel database.

The current project workspace has no main Flask application or team database, so the Blueprint has not been registered or integrated with the team's backend. The temporary database used by API tests is deleted after each test.

### Run API tests

From this `machine_learning/` directory:

```powershell
py -m unittest discover -s tests -v
```
