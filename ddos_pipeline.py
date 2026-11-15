#!/usr/bin/env python3
"""
CIC-DDoS2019: sample -> clean -> reduce features -> train/compare -> report.

Usage:
  python ddos_pipeline.py --data_dir data/train                      # random split
  python ddos_pipeline.py --data_dir data/train --test_dir data/test # train-day vs test-day
Options: --frac 0.2 --max_per_label 20000 --topk 20 --out out
"""
import argparse, glob, os, time
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, ConfusionMatrixDisplay)

# identifiers / shortcut columns removed before anything else
DROP = {"flow id", "source ip", "destination ip", "source port", "destination port",
        "timestamp", "unnamed: 0", "simillarhttp", "inbound"}


def _clean(df):
    df = df.drop(columns=[c for c in df.columns if c in DROP])
    label = df.pop("label").astype(str).str.strip().str.lower()
    X = df.apply(pd.to_numeric, errors="coerce").astype("float32")
    X = X.replace([np.inf, -np.inf], np.nan)
    X["label"] = label.values
    return X


def load_sample(folder, frac, seed, chunk=200_000):
    files = sorted(glob.glob(os.path.join(folder, "**", "*.csv"), recursive=True)
                   + glob.glob(os.path.join(folder, "**", "*.parquet"), recursive=True))
    if not files:
        raise SystemExit(f"No csv/parquet files found under {folder}")
    parts = []
    for f in files:
        print("reading", f)
        chunks = [pd.read_parquet(f)] if f.endswith(".parquet") else \
            pd.read_csv(f, chunksize=chunk, low_memory=False)
        for df in chunks:
            df.columns = df.columns.astype(str).str.strip().str.lower()
            # sample inside every chunk, so each file/attack type is represented
            parts.append(_clean(df.sample(frac=frac, random_state=seed)))
    return pd.concat(parts, ignore_index=True)


def prepare(folder, frac, cap, seed):
    df = load_sample(folder, frac, seed)
    n0 = len(df)
    df = df.dropna().drop_duplicates().reset_index(drop=True)
    print(f"{folder}: {n0} sampled -> {len(df)} after dropna + dedup")
    print(df.label.value_counts().to_string())
    # cap per label so training finishes in minutes on a laptop
    df = pd.concat([g.sample(min(len(g), cap), random_state=seed)
                    for _, g in df.groupby("label")], ignore_index=True)
    return df


def split_xy(df):
    return df.drop(columns="label"), (df.label != "benign").astype(int), df.label


def select_features(X, y, k, seed):
    X = X.loc[:, X.nunique() > 1]                                  # constant columns
    corr = X.corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
    X = X.drop(columns=[c for c in upper.columns if (upper[c] > 0.95).any()])  # redundant
    sub = X.sample(min(len(X), 100_000), random_state=seed)
    rf = RandomForestClassifier(n_estimators=50, n_jobs=-1, class_weight="balanced",
                                random_state=seed).fit(sub, y.loc[sub.index])
    imp = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)
    return list(imp.head(k).index), imp, X.shape[1]


def evaluate(name, model, Xtr, ytr, Xte, yte, seed):
    if name == "KNN":                                              # KNN is slow, subsample
        idx = Xtr.sample(min(len(Xtr), 50_000), random_state=seed).index
        Xtr, ytr = Xtr.loc[idx], ytr.loc[idx]
    t = time.time(); model.fit(Xtr, ytr); t_train = time.time() - t
    t = time.time(); pred = model.predict(Xte); t_pred = time.time() - t
    auc = roc_auc_score(yte, model.predict_proba(Xte)[:, 1]) if hasattr(model, "predict_proba") else np.nan
    row = {"model": name, "n_features": Xtr.shape[1],
           "accuracy": accuracy_score(yte, pred),
           "precision": precision_score(yte, pred, zero_division=0),
           "recall_attack": recall_score(yte, pred, zero_division=0),
           "recall_benign": recall_score(yte, pred, pos_label=0, zero_division=0),
           "f1": f1_score(yte, pred, zero_division=0), "roc_auc": auc,
           "train_s": round(t_train, 1), "predict_s": round(t_pred, 2)}
    print(row)
    return row, pred


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data_dir", required=True)
    ap.add_argument("--test_dir")
    ap.add_argument("--frac", type=float, default=0.2)
    ap.add_argument("--max_per_label", type=int, default=20_000)
    ap.add_argument("--topk", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    data = prepare(a.data_dir, a.frac, a.max_per_label, a.seed)
    if a.test_dir:
        tr, te = data, prepare(a.test_dir, a.frac, a.max_per_label, a.seed)
    else:
        tr, te = train_test_split(data, test_size=0.3, random_state=a.seed,
                                  stratify=(data.label != "benign"))
    Xtr, ytr, _ = split_xy(tr.reset_index(drop=True))
    Xte, yte, raw_te = split_xy(te.reset_index(drop=True))
    Xte = Xte.reindex(columns=Xtr.columns, fill_value=0)
    print(f"train {Xtr.shape}, test {Xte.shape}, attack share train {ytr.mean():.3f}")

    # feature selection uses TRAIN data only
    feats, imp, n_after_filter = select_features(Xtr, ytr, a.topk, a.seed)
    print(f"{Xtr.shape[1]} features -> {n_after_filter} after constant/corr filter -> top {len(feats)}")
    imp.to_csv(os.path.join(a.out, "feature_importance.csv"))
    pd.Series(feats).to_csv(os.path.join(a.out, "selected_features.csv"), index=False, header=["feature"])

    models = {
        "DecisionTree": DecisionTreeClassifier(class_weight="balanced", random_state=a.seed),
        "RandomForest": RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                               class_weight="balanced", random_state=a.seed),
        "LogisticRegression": make_pipeline(StandardScaler(),
                                            LogisticRegression(max_iter=1000, class_weight="balanced")),
        "NaiveBayes": GaussianNB(),
        "KNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5, n_jobs=-1)),
    }
    rows, preds = [], {}
    for name, m in models.items():
        row, preds[name] = evaluate(name, m, Xtr[feats], ytr, Xte[feats], yte, a.seed)
        rows.append(row)
    # baseline: same RF on ALL features, to show what feature reduction costs/saves
    base = RandomForestClassifier(n_estimators=100, n_jobs=-1, class_weight="balanced", random_state=a.seed)
    row, _ = evaluate("RandomForest_all_features", base, Xtr, ytr, Xte, yte, a.seed)
    rows.append(row)

    res = pd.DataFrame(rows).round(4)
    res.to_csv(os.path.join(a.out, "results.csv"), index=False)
    print("\n" + res.to_string(index=False))

    # per-attack-type recall for RF (which attacks does it miss?)
    p = pd.Series(preds["RandomForest"], index=raw_te.index)
    per = (p[raw_te != "benign"] == 1).groupby(raw_te[raw_te != "benign"]).agg(["mean", "size"])
    per.columns = ["recall", "n_test"]
    per.round(4).to_csv(os.path.join(a.out, "per_attack_recall.csv"))
    print("\nPer-attack recall (RandomForest):\n" + per.round(4).to_string())

    # figures
    imp.head(a.topk)[::-1].plot.barh(figsize=(7, 6), title="Top feature importances")
    plt.tight_layout(); plt.savefig(os.path.join(a.out, "feature_importance.png"), dpi=150); plt.close()
    ConfusionMatrixDisplay.from_predictions(yte, preds["RandomForest"],
                                            display_labels=["benign", "attack"])
    plt.title("Random Forest"); plt.savefig(os.path.join(a.out, "cm_rf.png"), dpi=150); plt.close()

    # keep the model so a prevention layer can load it later
    rf = models["RandomForest"]
    joblib.dump({"model": rf, "features": feats}, os.path.join(a.out, "rf_ddos.joblib"))
    print("\nSaved results, figures and rf_ddos.joblib to", a.out)


if __name__ == "__main__":
    main()