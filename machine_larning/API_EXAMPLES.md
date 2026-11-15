# API examples (real output from the running server; data SIMULATED)

## POST /api/security/score  (normal session -> no alert)
Request
```json
{"session_id": "SIM-000101", "failed_logins": 0, "requests_per_minute": 5, "login_attempts": 1,
 "token_requests": 1, "distinct_accounts_per_ip": 1, "avg_gap_between_requests": 12,
 "session_duration": 240, "off_hours_flag": 0}
```
Response `200`
```json
{"session_id": "SIM-000101", "anomaly_score": 0.3269, "severity": "low",
 "reason": "Within normal range for simulated-normal baseline.", "action": "none",
 "alert_id": null, "alert_status": null, "advisory_only": true, "simulated": false,
 "notice": "Advisory only. This module never blocks, delays or invalidates a vote. Alerts are for human review."}
```

## POST /api/security/score  (simulated brute force -> alert saved with status "new")
Request
```json
{"session_id": "SIM-000102", "ip_hash": "sim-attacker-demo", "failed_logins": 30,
 "requests_per_minute": 40, "login_attempts": 31, "token_requests": 0,
 "distinct_accounts_per_ip": 1, "avg_gap_between_requests": 1.5, "session_duration": 90,
 "off_hours_flag": 1, "simulated": true}
```
Response `200`
```json
{"session_id": "SIM-000102", "anomaly_score": 0.7637, "severity": "high",
 "reason": "many failed logins (failed_logins, z=+19.3); many login attempts (login_attempts, z=+17.7); resembles brute-force login.",
 "action": "human_review", "alert_id": 3, "alert_status": "new", "advisory_only": true, "simulated": true,
 "notice": "Advisory only. This module never blocks, delays or invalidates a vote. Alerts are for human review."}
```

## POST /api/security/score  (rejected: personal field)
Request `{"failed_logins": 3, "email": "a@b.com"}` -> Response `400`
```json
{"error": "invalid_request",
 "details": ["unexpected field(s): email (only the 8 numeric features plus session_id/ip_hash are accepted; no personal, candidate or ballot data)"]}
```

## GET /api/security/alerts?status=new&limit=2
Response `200` (query params: `status`, `severity`, `limit` max 200, `offset`)
```json
{"count": 1, "notice": "Advisory only. This module never blocks, delays or invalidates a vote. Alerts are for human review.",
 "alerts": [{"id": 3, "created_at": "2026-11-15 09:34:54", "session_id": "SIM-000102",
   "ip_hash": "sim-attacker-demo", "window_start": null, "window_end": null,
   "anomaly_score": 0.7637, "severity": "high",
   "reason": "many failed logins (failed_logins, z=+19.3); many login attempts (login_attempts, z=+17.7); resembles brute-force login.",
   "features": {"failed_logins": 30, "requests_per_minute": 40, "login_attempts": 31, "token_requests": 0,
                "distinct_accounts_per_ip": 1, "avg_gap_between_requests": 1.5, "session_duration": 90, "off_hours_flag": 1},
   "is_simulated": true, "status": "new", "reviewed_by": null, "reviewed_at": null}]}
```

## GET /api/security/summary
Response `200`
```json
{"total_alerts": 3, "alerts_last_24h": 3, "simulated_alerts": 3, "activity_log_rows": 388,
 "by_severity": {"low": 0, "medium": 0, "high": 3},
 "by_status": {"new": 3, "reviewed": 0, "dismissed": 0},
 "latest_alert": {"id": 3, "severity": "high", "status": "new", "...": "..."},
 "model": {"type": "isolation_forest", "trained_on": "SIMULATED", "contamination": 0.03,
           "thresholds": {"medium": 0.5457, "high": 0.5757}},
 "generated_at": "2026-11-15 09:34:54",
 "notice": "Advisory only. This module never blocks, delays or invalidates a vote. Alerts are for human review."}
```
