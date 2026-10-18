"""
NeuralPhish Model Training & Validation Pipeline
Reproducible training script for Phishing URL Detection using NLP CountVectorization
and Multinomial Naive Bayes.
"""

import argparse
import os
import pickle
import sys
import time
from typing import Tuple

import numpy as np
from nltk.stem.snowball import SnowballStemmer
from nltk.tokenize import RegexpTokenizer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB


def get_preprocessor():
    tokenizer = RegexpTokenizer(r"[A-Za-z]+")
    stemmer = SnowballStemmer("english")

    def stem_and_tokenize(url: str) -> str:
        tokens = tokenizer.tokenize(url)
        stemmed = [stemmer.stem(t) for t in tokens]
        return " ".join(stemmed)

    return stem_and_tokenize


def create_synthetic_benchmark():
    """Generates a small representative benchmark if full dataset is not present."""
    phishing_samples = [
        "http://paypal-verification-account-security-update.xyz/login",
        "https://netflix-billing-renew.xyz/auth",
        "http://amazon-anniversary-prize.top/claim",
        "http://kyc-update-sbi-portal.xyz/verify",
        "http://fedex-parcel-redelivery.online/track",
        "http://apple-id-verify-secure.top/auth",
        "http://secure-login-chase-portal.xyz/signin",
        "http://whatsapp-security-code.cf/verify",
        "http://192.168.1.100/admin/login",
        "http://bankofamerica-urgent-update.info/auth"
    ] * 20

    benign_samples = [
        "https://google.com/search?q=machine+learning",
        "https://github.com/torvalds/linux",
        "https://python.org/doc/tutorial",
        "https://wikipedia.org/wiki/Artificial_intelligence",
        "https://amazon.com/dp/B08N5WRWNW",
        "https://apple.com/iphone-15-pro",
        "https://microsoft.com/en-us/windows",
        "https://stackoverflow.com/questions/123456",
        "https://linkedin.com/in/swastik-kumar",
        "https://youtube.com/watch?v=dQw4w9WgXcQ"
    ] * 20

    urls = phishing_samples + benign_samples
    labels = ["bad"] * len(phishing_samples) + ["good"] * len(benign_samples)
    return urls, labels


def train(dataset_path: str = None, output_dir: str = None, test_size: float = 0.2):
    print("=" * 65)
    print("  NeuralPhish NLP Model Training Pipeline")
    print("=" * 65)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    if output_dir is None:
        output_dir = base_dir

    stem_fn = get_preprocessor()

    # Load dataset
    if dataset_path and os.path.exists(dataset_path):
        import pandas as pd
        print(f"[*] Loading dataset from: {dataset_path}")
        df = pd.read_csv(dataset_path)
        # Normalize column names
        cols = {c.lower(): c for c in df.columns}
        url_col = cols.get("url", "URL")
        label_col = cols.get("label", "Label")
        df = df.dropna(subset=[url_col, label_col])
        urls = df[url_col].astype(str).tolist()
        labels = df[label_col].astype(str).tolist()
        print(f"[+] Loaded {len(urls):,} records.")
    else:
        print("[*] No dataset CSV specified or file not found. Running synthetic benchmark mode...")
        urls, labels = create_synthetic_benchmark()
        print(f"[+] Generated {len(urls)} sample records for pipeline validation.")

    print("[*] Preprocessing URLs (Regexp Alphabetic Tokenization + Snowball Stemming)...")
    start_t = time.time()
    processed_urls = [stem_fn(u) for u in urls]
    print(f"[+] Preprocessing completed in {time.time() - start_t:.2f}s")

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        processed_urls, labels, test_size=test_size, random_state=42, stratify=labels
    )
    print(f"[*] Train set: {len(X_train):,} samples | Test set: {len(X_test):,} samples")

    # Vectorize
    print("[*] Fitting CountVectorizer...")
    vectorizer = CountVectorizer()
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"[+] Vocabulary size: {len(vectorizer.vocabulary_):,} unique n-grams.")

    # Train MultinomialNB
    print("[*] Training Multinomial Naive Bayes Classifier...")
    model = MultinomialNB(alpha=1.0)
    model.fit(X_train_vec, y_train)

    # Evaluate
    print("[*] Evaluating model on unseen holdout test set...")
    y_pred = model.predict(X_test_vec)
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred))

    # Save artifacts
    model_file = os.path.join(output_dir, "phising.pkl")
    vec_file = os.path.join(output_dir, "vectorizer.pkl")

    print(f"[*] Serializing artifacts to: {output_dir}")
    with open(model_file, "wb") as f:
        pickle.dump(model, f)
    with open(vec_file, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"[+] Successfully exported model -> {model_file}")
    print(f"[+] Successfully exported vectorizer -> {vec_file}")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="NeuralPhish Model Training & Validation")
    parser.add_argument("--dataset", "-d", help="Path to CSV dataset containing URL and Label columns.")
    parser.add_argument("--output", "-o", help="Target output directory for pickled models.")
    parser.add_argument("--test-size", type=float, default=0.2, help="Holdout test split ratio (default: 0.2).")
    args = parser.parse_args()

    train(dataset_path=args.dataset, output_dir=args.output, test_size=args.test_size)


if __name__ == "__main__":
    main()
