#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier,IsolationForest,HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
	classification_report,
	confusion_matrix,
	precision_recall_fscore_support
)


from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder,StandardScaler,FunctionTransformer

def load_dataset(path):
	path = Path(path)
	if path.suffix == ".parquet":
		return pd.read_parquet(path)

	if path.suffix == ".csv":
		return pd.read_csv(path)

	return pd.read_json(path, lines=True)

def prepare_dataframe(df):
	df = df.copy()

	required = [
		"full_log",
		"rule_level",
		"agent_name",
		"rule_id",
		"multi_class_label",
		"binary_label",
		"confidence",
		"correlation_status"
	]

	for col in required:
		if col not in df.columns:
			df[col] = ""

	df["full_log"] = df["full_log"].fillna("")
	df["rule_level"] = pd.to_numeric(df["rule_level"], errors="coerce").fillna(0)
	df["agent_name"] = df["agent_name"].fillna("unknown")
	df["rule_id"] = df["rule_id"].fillna("unknown").astype(str)
	df["correlation_status"] = df["correlation_status"].fillna("unknown")
	df["binary_label"] = df["binary_label"].fillna("unlabeled")

	# Untuk baseline supervised, buang unlabeled.
	df = df[df["binary_label"].isin(["benign", "malicious"])]

	return df

def _to_dense(x):
	"""Convert sparse matrix to dense for HistGradientBoostingClassifier."""
	return x.toarray() if hasattr(x, "toarray") else x


def make_supervised_pipeline(model):
	text_col = "full_log"
	numeric_cols = ["rule_level"]
	categorical_cols = ["agent_name", "rule_id", "correlation_status"]

	preprocessor = ColumnTransformer(
		transformers=[
			("text", TfidfVectorizer(max_features=2000, ngram_range=(1, 2)), text_col),
			("num", StandardScaler(), numeric_cols),
			("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
		]
	)

	# HistGradientBoostingClassifier needs dense input
	if isinstance(model, HistGradientBoostingClassifier):
		return Pipeline(
			steps=[
				("features", preprocessor),
				("to_dense", FunctionTransformer(_to_dense, accept_sparse=True)),
				("model", model)
			]
		)

	return Pipeline(
		steps=[
			("features", preprocessor),
			("model", model)
		]
	)

def false_rates(cm):
	# Binary: labels sorted benign, malicious
	if cm.shape != (2, 2):
		return {"false_positive_rate": None, "false_negative_rate": None}

	tn, fp, fn, tp = cm.ravel()

	fpr = fp / (fp + tn) if (fp + tn) else 0.0
	fnr = fn / (fn + tp) if (fn + tp) else 0.0

	return {
		"false_positive_rate": round(fpr, 4),
		"false_negative_rate": round(fnr, 4)
	}

def train_supervised_models(df, outdir):
	X = df[["full_log", "rule_level", "agent_name", "rule_id", "correlation_status"]]
	y = df["binary_label"]

	label_counts = y.value_counts().to_dict()

	if len(label_counts) < 2:
		raise SystemExit("Dataset supervised butuh minimal dua kelas: benign dan malicious")

	test_size = 0.3 if len(df) >= 20 else 0.5

	X_train, X_test, y_train, y_test = train_test_split(
		X,
		y,
		test_size=test_size,
		random_state=42,
		stratify=y if min(label_counts.values()) >= 2 else None
	)
	models = {
		"logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
		"random_forest": RandomForestClassifier(
			n_estimators=200,
			random_state=42,
			class_weight="balanced"
		),
		"hist_gradient_boosting": HistGradientBoostingClassifier(random_state=42)
	}

	results = {}

	for name, model in models.items():
		pipe = make_supervised_pipeline(model)
		pipe.fit(X_train, y_train)

		pred = pipe.predict(X_test)

		labels = ["benign", "malicious"]
		cm = confusion_matrix(y_test, pred, labels=labels)
		report = classification_report(y_test, pred, output_dict=True, zero_division=0)

		rates = false_rates(cm)

		results[name] = {
			"labels": labels,
			"confusion_matrix": cm.tolist(),
			"classification_report": report,
			"false_positive_rate":
			rates["false_positive_rate"],
			"false_negative_rate":
			rates["false_negative_rate"],
			"train_records": len(X_train), "test_records": len(X_test)
		}

		joblib.dump(pipe, outdir / f"{name}.joblib")

	return results

def train_isolation_forest(df, outdir):
	# Isolation Forest baseline untuk anomaly-style scoring.
	features = pd.DataFrame({
		"rule_level": pd.to_numeric(df["rule_level"], errors="coerce").fillna(0),
		"full_log_length": df["full_log"].fillna("").str.len()
	})

	model = IsolationForest(
		n_estimators=200,
		contamination="auto",
		random_state=42
	)

	model.fit(features)

	scores = model.decision_function(features)
	pred = model.predict(features)

	result = {
		"records": len(df),
		"score_min": float(scores.min()),
		"score_max": float(scores.max()),
		"anomaly_count": int((pred == -1).sum()),
		"normal_count": int((pred == 1).sum()),
		"note": "Isolation Forest dipakai sebagai anomaly baseline, bukan classifier final."
	}

	joblib.dump(model, outdir / "isolation_forest.joblib")

	return result

def rule_based_baseline(df):
	# Baseline sederhana: rule_level >= 7 dianggap malicious.
	y_true = df["binary_label"]
	y_pred = df["rule_level"].apply(lambda x: "malicious" if x >= 7 else "benign")

	labels = ["benign", "malicious"]
	cm = confusion_matrix(y_true, y_pred, labels=labels)
	report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
	rates = false_rates(cm)

	return {
		"rule": "rule_level >= 7 -> malicious else benign",
		"labels": labels,
		"confusion_matrix": cm.tolist(),
		"classification_report": report,
		"false_positive_rate": rates["false_positive_rate"],
		"false_negative_rate": rates["false_negative_rate"]
	}

def main():
	parser = argparse.ArgumentParser(description="Train baseline models for AI SOC Wazuh dataset")
	parser.add_argument("--dataset", default="datasets/final/dataset.parquet")
	parser.add_argument("--output-dir", default="models")
	parser.add_argument("--report", default="reports/final/model_baseline_report.json")
	args = parser.parse_args()

	outdir = Path(args.output_dir)
	outdir.mkdir(parents=True, exist_ok=True)

	df = load_dataset(args.dataset)
	df = prepare_dataframe(df)

	results = {
		"dataset": args.dataset,
		"records_used": len(df),
		"label_distribution": df["binary_label"].value_counts().to_dict(),
		"supervised_models": train_supervised_models(df, outdir),
		"isolation_forest": train_isolation_forest(df, outdir),
		"rule_based_baseline": rule_based_baseline(df)
	}

	report_path = Path(args.report)
	report_path.parent.mkdir(parents=True, exist_ok=True)
	report_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()
