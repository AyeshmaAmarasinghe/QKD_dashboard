# Artifact drop folder

The dashboard opens and runs with this folder empty. Anything placed here is
loaded read-only and verified before use; nothing here is ever trained,
re-fitted or modified by the dashboard.

Expected layout (all optional — see `dashboard/config.py` to point elsewhere):

    artifacts/
      nids/                              <- export from nids-model-15-09-2026.ipynb
        nids_inference_bundle.joblib
        nids_run_metadata.json
        nids_artifact_manifest.json
        deployability.json
        network_feature_pool.csv
      qkd_anomaly_detector.joblib        <- joblib dump of a trained QKDAnomalyDetector
      pool_forecaster.joblib             <- joblib dump of a fitted PoolDemandForecaster
      fusion_weights.json                <- {"w_qkd": 0.7}
      baseline_summary.csv               <- a summary the notebook already produced

Only trusted local research artifacts belong here. The dashboard deliberately
offers no upload control: loading an arbitrary pickle would execute arbitrary
code.
