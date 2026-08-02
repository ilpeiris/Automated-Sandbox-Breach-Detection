# Automated Sandbox Breach Detection

**Aho-Corasick pre-filtering engine for high-speed log triage, command-injection payload detection, and LLM log-analysis cost reduction.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Jupyter](https://img.shields.io/badge/Jupyter-Notebook-orange)
![License](https://img.shields.io/badge/License-MIT-green)

<p align="center">
  <img
    src="https://orca.security/wp-content/uploads/2026/07/blog-rapid-response-openai-agents-escape-sandbox-breach-huggingface-1.png?w=1044"
    alt="OpenAI Agents Sandbox Escape"
    width="800">
</p>

This repository contains a reference implementation and empirical evaluation notebook for a deterministic multi-pattern matching engine built on the **Aho-Corasick** algorithm.

The engine scans log text once and detects known malicious command-injection signatures in linear time. It is designed to act as a lightweight **gatekeeper** before more expensive analysis stages such as LLM inference, SIEM enrichment, anomaly detection, or human review.

> **Goal:** reduce the volume of logs sent to expensive downstream analysis by filtering known malicious patterns quickly, deterministically, and cheaply.

---

## Table of Contents

- [Overview](#overview)
- [What the Notebook Does](#what-the-notebook-does)
- [Repository Structure](#repository-structure)
- [Requirements](#requirements)
- [Data Setup](#data-setup)
- [Quick Start](#quick-start)
- [Example Notebook Output](#example-notebook-output)
- [Benchmark Results](#benchmark-results)
- [Security Evaluation](#security-evaluation)
- [Signature Refinement Experiment](#signature-refinement-experiment)
- [Space Complexity Analysis](#space-complexity-analysis)
- [Unit Tests](#unit-tests)
- [Algorithm and Complexity Summary](#algorithm-and-complexity-summary)
- [Generated Artifacts](#generated-artifacts)
- [Limitations](#limitations)
- [Datasets and Sources](#datasets-and-sources)
- [Responsible Use](#responsible-use)
- [Possible Extensions](#possible-extensions)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Overview

Modern systems generate extremely large volumes of log data. Sending all raw logs directly to expensive analysis pipelines, especially LLM-based analyzers, is often impractical due to:

- high token cost,
- context-window limits,
- latency,
- noisy benign traffic,
- and the need for real-time triage.

This project implements a pre-filtering engine using **Aho-Corasick**, a classical multi-pattern string-matching algorithm.

The engine builds a Trie of known malicious signatures, constructs failure links using BFS, and then scans incoming text in a single pass.

This makes it suitable for detecting known command-injection patterns such as:

```text
sleep 5
cat /etc/passwd
|| whoami
; id
rm -rf /
```

The notebook evaluates:

- construction time,
- scanning throughput,
- comparison against naive matching,
- comparison against Python’s optimized `in` operator,
- false-negative rate,
- false-positive rate,
- precision,
- F1-score,
- signature-length filtering,
- and Trie space complexity.

---

## What the Notebook Does

The main notebook is:

```text
Automated-Sandbox-Breach-Detection.ipynb
```

It is divided into the following phases:

### Phase 1 - Aho-Corasick Engine Build

Implements:

- `TrieNode`
- `AhoCorasick`
- pattern insertion
- BFS-based failure-link construction
- output inheritance for overlapping patterns
- single-pass search

### Phase 2 - Data Ingestion

Loads malicious command-injection signatures from:

1. A local Kaggle CSV dataset:
   ```text
   command-injection.csv
   ```

2. A local PayloadsAllTheThings text file:
   ```text
   command-execution-unix.txt
   ```

If the local text file is missing, the notebook attempts to fetch it from GitHub.

The signatures are merged and deduplicated.

### Phase 3 - Aho-Corasick Benchmark

Builds the automaton from the compiled signature set and scans a simulated polyglot payload.

Example payload:

```text
Summarize this file: / $(sleep 5) `sleep 5``*/-sleep(5)-"||sleep(5)||"/etc/passwd
```

### Phase 4 - Reference Baseline

Compares the Aho-Corasick scan against Python’s native `in` operator on the same prompt.

### Phase 5 - Scaled Benchmark

Compares three approaches across increasing input sizes:

1. Pure naive character-by-character matching
2. Python native `in` operator
3. Aho-Corasick engine

Each input size is benchmarked over multiple runs, and median execution times are reported.

### Phase 6 - Security Evaluation

Evaluates:

- recall,
- false-negative rate,
- specificity,
- false-positive rate.

Malicious payloads are wrapped in a log-like context:

```text
user_input: {payload}
```

Benign logs are evaluated using the Loghub OpenSSH dataset.

### Phase 7 - Signature Refinement Experiment

Removes overly short and generic signatures, then re-evaluates:

- recall against the original signature set,
- false-negative rate,
- specificity,
- false-positive rate,
- precision,
- F1-score.

### Phase 8 - Space Complexity Analysis

Measures:

- Trie node count,
- edge count,
- maximum Trie depth,
- total output entries,
- estimated memory usage,
- nodes-per-character ratio.

### Final Step — Unit Tests

Runs assertion-based tests for:

- exact matching,
- overlapping patterns,
- suffix matches,
- no-match cases,
- multiple repeated matches,
- empty-pattern handling.

---

## Repository Structure

A simple repository layout:

```text
Automated-Sandbox-Breach-Detection/
├── Automated-Sandbox-Breach-Detection.ipynb
├── README.md
├── LICENSE
├── requirements.txt
├── command-injection.csv              # required for full signature set
├── command-execution-unix.txt         # optional; notebook can fetch remotely
└── openssh_benign_logs.txt            # optional; notebook can fetch remotely
```

Generated artifacts may include:

```text
throughput_benchmark_results.csv
benchmark_results.png
fnr_fpr_comparison.csv
fnr_fpr_comparison_chart.png
space_complexity_comparison.csv
```

---

## Requirements

- Python 3.10+
- Jupyter Notebook or JupyterLab
- pandas
- matplotlib

The notebook also uses Python standard-library modules:

- `collections`
- `typing`
- `time`
- `urllib`
- `sys`
- `os`

Install dependencies with:

```bash
pip install -r requirements.txt
```

Example `requirements.txt`:

```text
jupyterlab>=4.0
pandas>=2.0
matplotlib>=3.7
```

---

## Data Setup

For full reproduction of the notebook results, place the following files in the same directory as the notebook:

```text
command-injection.csv
command-execution-unix.txt
openssh_benign_logs.txt
```

### 1. Kaggle command-injection dataset

Download from:

```text
https://www.kaggle.com/datasets/sanketpawase/os-command-injection
```

Ensure the CSV is available as:

```text
command-injection.csv
```

The notebook expects columns including:

```text
Label
sentence
```

It filters rows where:

```python
Label == 1
```

and extracts the `sentence` column as malicious payloads.

If `command-injection.csv` is missing, the notebook will still run, but with a reduced signature set.

---

### 2. PayloadsAllTheThings Unix command-execution payloads

Download manually or use:

```bash
curl -L -o command-execution-unix.txt \
  https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt
```

If this file is missing, the notebook will attempt to fetch it from the same GitHub URL.

---

### 3. Loghub OpenSSH benign logs

Download manually or use:

```bash
curl -L -o openssh_benign_logs.txt \
  https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log
```

If this file is missing, the notebook will attempt to fetch it from Loghub’s GitHub repository.

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Automated-Sandbox-Breach-Detection.git
cd Automated-Sandbox-Breach-Detection
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Download or place the datasets in the repository folder.

Then launch the notebook:

```bash
jupyter lab Automated-Sandbox-Breach-Detection.ipynb
```

Run all cells.

---

## Example Notebook Output

With the full dataset present, the notebook produces output similar to:

```text
[ ] Initiating Data Ingestion...
[+] Loaded 514 signatures from local Kaggle CSV.
[+] Loaded 83 signatures from local TXT file.
==================================================
[SUCCESS] Total unique malicious signatures compiled: 492
==================================================
```

Engine construction and scan example:

```text
[*] Initializing Aho-Corasick Engine...
[+] Trie & Failure Links built in 0.094552 seconds across 492 signatures.

[*] Scanning incoming prompt (80 characters)...
[+] Aho-Corasick scan completed in 0.000108 seconds.
[!] Threats Detected: 5
 Sample match: (25, 'sleep 5')
```

Reference baseline comparison:

```text
[Native 'in'] Scan completed in 0.000323 seconds.
[Aho-Corasick] Scan completed in 0.000108 seconds.
[+] SPEEDUP: The Aho-Corasick engine is 2.99x faster than Python's native C-optimized search!
```

Exact timings vary by machine, Python version, and dataset.

---

## Benchmark Results

The scaled benchmark compares:

1. **Pure naive matching**  
   Character-by-character comparison for every signature.

2. **Python native `in` operator**  
   Highly optimized C-level substring search.

3. **Aho-Corasick**  
   Single-pass automaton-based multi-pattern matching.

Representative median results from the notebook:

| Input Size (chars) | Pure Naive Median (s) | Native `in` Median (s) | Aho Median (s) | Speedup vs Native `in` |
|---:|---:|---:|---:|---:|
| 80 | 0.033274 | 0.000094 | 0.000042 | 2.23x |
| 400 | 0.040670 | 0.000120 | 0.000090 | 1.33x |
| 800 | 0.084640 | 0.000153 | 0.000131 | 1.16x |
| 2,000 | 0.223416 | 0.000215 | 0.000291 | 0.74x |
| 4,000 | 0.459472 | 0.000319 | 0.000538 | 0.59x |
| 8,000 | 0.931335 | 0.000495 | 0.001031 | 0.48x |
| 20,000 | 2.340800 | 0.001026 | 0.002482 | 0.41x |
| 40,000 | 4.837113 | 0.005131 | 0.005057 | ~1.0x |

### Interpretation

The pure naive baseline shows the expected poor scaling behavior.

Python’s native `in` operator is very fast because it is implemented in C. On smaller inputs, it can outperform a pure-Python Trie traversal.

However, as input size grows, Aho-Corasick becomes competitive again. At around 40,000 characters in the notebook run, Aho-Corasick approximately matches the native `in` baseline while still checking all signatures in a single pass.

The key advantage of Aho-Corasick is not only raw speed in Python, but predictable multi-pattern scanning behavior as the number of signatures grows.

---

## Security Evaluation

The notebook evaluates detection behavior using:

- 492 unique malicious command-injection signatures,
- 2,000 benign OpenSSH log lines from Loghub.

### Unfiltered engine: malicious payload detection

| Metric | Value |
|---|---:|
| Malicious payloads tested | 492 |
| True positives | 492 |
| False negatives | 0 |
| Recall | 100.00% |
| False-negative rate | 0.00% |

### Unfiltered engine: benign log evaluation

| Metric | Value |
|---|---:|
| Benign log lines tested | 2,000 |
| True negatives | 1,354 |
| False positives | 646 |
| Specificity | 67.70% |
| False-positive rate | 32.30% |

Example false positive from the notebook:

```text
Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown
```

Matched signature:

```text
; 
```

This happens because short delimiter-style signatures can appear naturally in benign logs.

---

## Signature Refinement Experiment

To reduce false positives, the notebook applies a minimum signature-length filter:

```python
MIN_PATTERN_LENGTH = 4
```

This removes 17 overly short or generic signatures.

The filtered engine is rebuilt using:

```text
475 signatures
```

However, it is evaluated against the original full set of:

```text
492 signatures
```

This gives an honest measure of what is missed by removing short signatures.

### Before/after comparison

| Metric | Unfiltered | Filtered, min length = 4 |
|---|---:|---:|
| Dictionary size | 492 | 475 |
| Original malicious corpus size | 492 | 492 |
| Recall | 100.00% | 96.54% |
| False-negative rate | 0.00% | 3.46% |
| Specificity | 67.70% | 100.00% |
| False-positive rate | 32.30% | 0.00% |
| Precision | 43.23% | 100.00% |
| F1-score | 60.36% | 98.24% |

### Interpretation

Filtering short signatures causes a small recall decrease:

```text
100.00% → 96.54%
```

But it eliminates false positives on the tested benign corpus:

```text
32.30% → 0.00%
```

and improves F1-score substantially:

```text
60.36% → 98.24%
```

Precision and F1-score are reported over the combined test corpora rather than a realistic operational traffic distribution. In a deployed system, precision would depend on the true proportion of malicious to benign log traffic.

The 17 missed payloads correspond to the removed short signatures, including short delimiters and short commands such as:

```text
;
|
||
&
`
ls
pwd
dir
%0a
\n
\r
```

The exact removed list is printed by the notebook.

---

## Space Complexity Analysis

The notebook measures Trie structure using BFS traversal.

### Unfiltered engine

| Metric | Value |
|---|---:|
| Signatures | 492 |
| Total pattern characters | 19,646 |
| Trie nodes | 14,889 |
| Edges | 14,888 |
| Maximum Trie depth | 1,524 |
| Total output entries | 1,204 |
| Estimated memory usage | 2,442.73 KB |
| Nodes / total characters | 0.7579 |

### Filtered engine, minimum length = 4

| Metric | Value |
|---|---:|
| Signatures | 475 |
| Total pattern characters | 19,606 |
| Trie nodes | 14,883 |
| Edges | 14,882 |
| Maximum Trie depth | 1,524 |
| Total output entries | 839 |
| Estimated memory usage | 2,441.74 KB |
| Nodes / total characters | 0.7591 |

### Interpretation

The node count is below the total number of pattern characters because many signatures share prefixes.

Removing 17 short signatures barely changes the node count, but it significantly reduces output entries and false positives.

This shows that the false-positive problem was driven mainly by low-specificity short signatures, not by large structural complexity in the Trie.

---

## Unit Tests

The final notebook cell runs assertion-based tests.

The tests verify:

### Basic match

```text
User input: cat /etc/passwd && echo done
```

Expected match:

```text
cat /etc/passwd
```

### Overlapping and suffix matches

Input:

```text
ushers
```

Expected matches include:

```text
she
he
hers
```

This verifies failure-link construction and output inheritance.

### No-match case

Input:

```text
Safe string with no threats
```

Expected matches:

```text
none
```

### Multiple repeated matches

Input:

```text
he he he
```

Expected match count:

```text
3
```

### Empty pattern handling

The engine ignores empty patterns gracefully.

---

## Algorithm and Complexity Summary

Let:

- `L` = length of one pattern,
- `M` = total length of all inserted patterns,
- `N` = length of the input text,
- `Z` = number of matches reported.

### Time complexity

| Operation | Complexity |
|---|---:|
| Add one pattern | O(L) |
| Build Trie and failure links | O(M) |
| Scan text | O(N + Z) |

### Space complexity

The implementation uses sparse dictionaries for child transitions:

```python
children: Dict[str, TrieNode]
```

Therefore, unused character transitions are not allocated.

Practical space complexity is approximately:

```text
O(M)
```

The theoretical worst case can be expressed as:

```text
O(M × Σ)
```

where `Σ` is the alphabet size, but for typical ASCII payloads and sparse dictionaries, the practical memory usage is much closer to `O(M)`.

---

## Generated Artifacts

Running the notebook produces the following artifacts:

### Benchmark output

```text
throughput_benchmark_results.csv
benchmark_results.png
```

### Security refinement output

```text
fnr_fpr_comparison.csv
fnr_fpr_comparison_chart.png
```

### Space complexity output

```text
space_complexity_comparison.csv
```

These files are generated in the notebook working directory.

If you do not want to commit generated artifacts, add them to `.gitignore`.

Example:

```gitignore
# Generated artifacts
*.png
throughput_benchmark_results.csv
fnr_fpr_comparison.csv
space_complexity_comparison.csv
```

---

## Limitations

This project is a reference implementation and evaluation notebook.

It has several important limitations.

### 1. Exact-match detection only

The engine detects signatures that appear exactly in the input.

It may miss:

- encoded payloads,
- obfuscated commands,
- fragmented commands,
- polymorphic attacks,
- zero-day patterns.

### 2. Short signatures can cause false positives

Short delimiters such as:

```text
;
|
&
`
```

can appear naturally in benign logs.

The notebook demonstrates this and applies a minimum-length filter to reduce false positives.

### 3. Not a complete security control

This engine should not be used as the only defense mechanism.

It is best used as a pre-filter or triage layer before:

- LLM analysis,
- SIEM correlation,
- anomaly detection,
- rule engines,
- human review.

### 4. Pure-Python implementation

The notebook implementation prioritizes clarity and reproducibility.

For very high-throughput production use, consider:

- compiled languages,
- C extensions,
- Rust bindings,
- SIMD optimizations,
- dedicated IDS engines,
- hardware acceleration.

---

## Datasets and Sources

This project uses publicly available datasets for evaluation.

### Kaggle OS Command Injection Dataset

```text
https://www.kaggle.com/datasets/sanketpawase/os-command-injection
```

Used for malicious command-injection payloads.

### PayloadsAllTheThings

```text
https://github.com/swisskyrepo/PayloadsAllTheThings
```

Used for Unix command-execution payloads.

Direct file used by the notebook:

```text
https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt
```

### Loghub OpenSSH Logs

```text
https://github.com/logpai/loghub
```

Used for benign OpenSSH log lines.

Direct file used by the notebook:

```text
https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log
```

Please review the licenses and terms of each dataset before redistribution or production use.

---

## Responsible Use

This project is intended for:

- research,
- education,
- log-analysis experimentation,
- security-tooling prototyping.

Use it only on systems, logs, and data you are authorized to analyze.

Do not use this project for unauthorized monitoring, attacks, or malicious activity.

---

## Possible Extensions

Possible future improvements include:

- packaging the engine as a reusable Python module,
- adding a command-line scanner,
- adding input normalization,
- adding URL-decoding and Base64-decoding preprocessing,
- adding token-boundary matching,
- adding allowlists,
- adding streaming log support,
- adding JSON output,
- adding Prometheus metrics,
- adding a REST API wrapper,
- adding AST-based command analysis,
- adding hardware-accelerated matching,
- integrating with LLM log-analysis pipelines.

---

## Contributing

Contributions are welcome.

Please:

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test the notebook.
5. Open a pull request with a clear description.

If you change benchmarking or evaluation logic, please include updated output tables or charts where relevant.

---

## Author

**M.D. Isuru Lakmal Peiris**

---

## License

This project is licensed under the MIT License.

```text
MIT License

Copyright (c) 2026 M.D. Isuru Lakmal Peiris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Acknowledgements

This project uses public datasets and resources from:

- Kaggle,
- PayloadsAllTheThings,
- Loghub.

The core algorithm is based on the classical Aho-Corasick multi-pattern string-matching algorithm.
