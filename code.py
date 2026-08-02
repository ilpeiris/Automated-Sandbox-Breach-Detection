# =========================================================================
# Author: M.D. Isuru Lakmal Peiris
# Automated Sandbox Breach Detection - Aho-Corasick Pre-Filtering Engine
# ===========================================================================

# ===========================================================================
# Phase 1: Aho-Corasick Engine Build (Custom Trie with Failure Links)
# ===========================================================================

from collections import deque
from typing import List, Dict, Optional, Tuple
import time
import pandas as pd

class TrieNode:
    """
    Represents a single character node within the Aho-Corasick automaton.
    """
    def __init__(self):
        # Dictionary mapping a character to its child TrieNode
        self.children: Dict[str, 'TrieNode'] = {}
        # Pointer to the next best fallback node if a mismatch occurs
        self.failure_link: Optional['TrieNode'] = None
        # List of malicious payloads that end at this specific node
        self.output_list: List[str] = []

class AhoCorasick:
    """
    Deterministic finite Automaton for high-speed multi-pattern matching.
    Time Complexity: O(N + M + Z) where N=text length, M=total pattern length, Z=matches.
    """
    def __init__(self):
        self.root = TrieNode()

    def add_pattern(self, pattern: str) -> None:
        """
        Inserts a malicious payload into the Trie structure.
        Time Complexity: O(L) where L is the length of the pattern.
        """
        if not pattern:
            return
        
        node = self.root
        for char in pattern:
            # If the path dosnt exist, create a new TrieNode
            if char not in node.children:
                node.children[char] = TrieNode()
            # Move to the child node
            node = node.children[char]
        # Mark the end of this malicious pattern
        node.output_list.append(pattern)

    def build_failure_links(self) -> None:
        """
        Constructs failure links using Breadth-First Search
        allows O(N) scanning by preventing backtracking.
        """
        queue = deque()
        
        # Initialize the first depth level (children of the root) 
        # The failure link of roots children always points back to root
        for char, child in self.root.children.items():
            child.failure_link = self.root
            queue.append(child)

        #  BFS Traversal through the rest of the Trie 
        while queue:
            current_node = queue.popleft()
            
            # Iterate through all children of the current node
            for char, child in current_node.children.items():
                queue.append(child)
                fallback = current_node.failure_link
                
                # Find the longest proper suffix 
                # Trace back through failure links until we find a node that has
                # a child matching 'char', we hit the root
                while fallback and char not in fallback.children:
                    fallback = fallback.failure_link
                
                # Assign the failure link 
                if fallback:
                    child.failure_link = fallback.children[char]
                else:
                    child.failure_link = self.root
                
                # Inherit outputs for overlapping patterns 
                # If the failure link points to a node that marks the end of a pattern,
                # propagate that pattern to the current child to catch overlaps
                if child.failure_link:
                    child.output_list.extend(child.failure_link.output_list)

    def search(self, text: str) -> List[Tuple[int, str]]:
        """
        Scans continuous text in O(N + Z) time complexity.
        N = length of text, Z = number of matches found.
        """
        node = self.root
        results = []
        
        # Iterate through the text character by character
        for i, char in enumerate(text):
            # Handle mismatch by following failure links
            # While having a node and the current character doest match a child,
            # follow the failure link to find a fallback state.
            while node and char not in node.children:
                node = node.failure_link
            
            # Reset to root if no match found
            # If node is None, it means we fell back to nothing, so restart at root
            if not node:
                node = self.root
                continue
            
            #Transition to the matching child node
            node = node.children[char]
            
            # Record any malicious patterns ending at this position
            # If the current node has output patterns, calculate their start index
            # and append them to our results list
            if node.output_list:
                for pattern in node.output_list:
                    start_index = i - len(pattern) + 1
                    results.append((start_index, pattern))
                    
        return results




# =============================================================================
# Phase 2: Data Ingestion (Local Priority with GitHub Fallback)
# ===========================================================================
import pandas as pd
import urllib.request
import urllib.error
import os

print("[*] Initiating Data Ingestion...")

# Source 1: Kaggle Dataset (Local CSV)
try:
    df = pd.read_csv("command-injection.csv")
    kaggle_payloads = df[df['Label'] == 1]['sentence'].dropna().astype(str).tolist()
    print(f"[+] Loaded {len(kaggle_payloads)} signatures from local Kaggle CSV.")
except FileNotFoundError:
    print("[!] ERROR: 'command-injection.csv' not found. Please ensure it is in the same directory.")
    kaggle_payloads = []

# Source 2: PayloadsAllTheThings (Local TXT with Dynamic GitHub Fallback)
github_payloads = []
try:
    # 1st Priority: Try reading the local downloaded file
    with open("command-execution-unix.txt", "r", encoding="utf-8") as f:
        github_payloads = [line.strip() for line in f.readlines() if line.strip()]
    print(f"[+] Loaded {len(github_payloads)} signatures from local TXT file.")
    
except FileNotFoundError:
    # 2nd Priority: Fallback to GitHub if local file is corrupted or blocked by security
    github_url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt"
    try:
        print("[*] Local TXT not found. Fetching from GitHub as fallback...")
        response = urllib.request.urlopen(github_url)
        raw_text = response.read().decode('utf-8')
        github_payloads = [line.strip() for line in raw_text.split('\n') if line.strip()]
        print(f"[+] Loaded {len(github_payloads)} signatures from GitHub.")
    except urllib.error.URLError as e:
        print(f"[-] Could not reach GitHub ({e.reason}). Falling back to Kaggle data only.")

# Merge and Deduplicate
cmdi_signatures = list(set(kaggle_payloads + github_payloads))

print("="*50)
print(f"[SUCCESS] Total unique malicious signatures compiled: {len(cmdi_signatures)}")
print("="*50)




# ==========================================================================
# Phase 3: Aho-Corasick Benchmark (O(N + M + Z))
# ==========================================================================


print("\n" + "="*50)
print("PHASE 3: Aho-Corasick Engine Benchmark")
print("="*50)

# Initialize the Engine
print("[*] Initializing Aho-Corasick Engine...")
waf_engine = AhoCorasick()

# Build the Automaton (Trie + Failure Links)
start_build = time.perf_counter()

for signature in cmdi_signatures:
    waf_engine.add_pattern(str(signature))

waf_engine.build_failure_links()  # Must be called after all patterns are inserted, before any search

end_build = time.perf_counter()
build_time = end_build - start_build

print(f"[+] Trie & Failure Links built in {build_time:.6f} seconds across {len(cmdi_signatures)} signatures.")

# Prepare a Complex Polyglot Payload (Simulating a Sandbox Escape Attempt)
simulated_prompt = 'Summarize this file: /*$(sleep 5)`sleep 5``*/-sleep(5)-"||sleep(5)||"/etc/passwd'
print(f"\n[*] Scanning incoming prompt ({len(simulated_prompt)} characters)...")

# Scan the Text using Aho-Corasick
start_scan = time.perf_counter()
threats_detected = waf_engine.search(simulated_prompt)  # Single-pass scan; O(N+Z) per call
end_scan = time.perf_counter()

scan_time = end_scan - start_scan

print(f"[+] Aho-Corasick scan completed in {scan_time:.6f} seconds.")
print(f"[!] Threats Detected: {len(threats_detected)}")
if threats_detected:
    print(f"    Sample match: {threats_detected[0]}")





#===========================================================================
# Phase 4: Reference Baseline (Python Native 'in' Operator)
# ==========================================================================

print("\n" + "="*50)
print("PHASE 4: Reference Baseline Benchmark (Python Native 'in')")
print("="*50)

# Run the native approach to compare against the Aho-Corasick speed
print("[*] Running Native Baseline (checking each pattern individually)...")
start_naive = time.perf_counter()

# For every pattern check if it exists using CPythons highly optimized Two-Way search
for pattern in cmdi_signatures:
    if pattern in simulated_prompt:
        pass  

end_naive = time.perf_counter()
naive_time = end_naive - start_naive

# Calculate the speedup factor
speedup = naive_time / scan_time if scan_time > 0 else float('inf')

print(f"[Native 'in'] Scan completed in {naive_time:.6f} seconds.")
print(f"[Aho-Corasick] Scan completed in {scan_time:.6f} seconds.")
print(f"[+] SPEEDUP: The Aho-Corasick engine is {speedup:.2f}x faster than Python's native C-optimized search!")

print("\n" + "="*50)
print("[NOTE] True O(N x M) complexity is demonstrated in the scaled Phase 5 benchmark.")
print("="*50)





# ========================================================================
# Phase 5: Scaled Benchmark & Visualization
# ========================================================================

import time
import matplotlib.pyplot as plt

print("\n" + "=" * 60)
print("PHASE 5: Scaled Benchmark & Visualization")
print("=" * 60)

# -----------------
# Configuration
# -----------------

base_prompt = (
    'Summarize this file: '
    '/*$(sleep 5)`sleep 5``*/-sleep(5)-"||sleep(5)||"/etc/passwd'
)

# Different input sizes
multipliers = [1, 5, 10, 25, 50, 100, 250, 500]

# Number of benchmark repetitions
RUNS = 5

text_lengths = []
aho_times = []
naive_times = []

print("[*] Running scaled benchmark...")

# ----------------
# Benchmark Loop
# ----------------

for mult in multipliers:

    test_text = base_prompt * mult

    text_lengths.append(len(test_text))

    # ======================
    # Aho-Corasick Benchmark
    # ======================

    aho_total = 0.0

    for _ in range(RUNS):

        start = time.perf_counter()

        waf_engine.search(test_text)

        end = time.perf_counter()

        aho_total += (end - start)

    aho_average = aho_total / RUNS

    aho_times.append(aho_average)

    # =====================================
    # TRUE Naive String Matching Benchmark
    # =====================================

    naive_total = 0.0

    for _ in range(RUNS):

        start = time.perf_counter()

        for pattern in cmdi_signatures:

            pattern_length = len(pattern)
            text_length = len(test_text)

            if pattern_length == 0:
                continue

            # Slide pattern across text
            for i in range(text_length - pattern_length + 1):

                matched = True

                # Compare character-by-character
                for j in range(pattern_length):

                    if test_text[i + j] != pattern[j]:
                        matched = False
                        break

                if matched:
                    pass

        end = time.perf_counter()

        naive_total += (end - start)

    naive_average = naive_total / RUNS

    naive_times.append(naive_average)

# ---------------
# Print Results
# ---------------

print("\nBenchmark Results")
print("-" * 85)

print(
    f"{'Input Size':<15}"
    f"{'Naive (s)':<18}"
    f"{'Aho (s)':<18}"
    f"{'Speedup':<15}"
)

print("-" * 85)

for length, naive, aho in zip(text_lengths, naive_times, aho_times):

    speedup = naive / aho if aho > 0 else float("inf")

    print(
        f"{length:<15}"
        f"{naive:<18.6f}"
        f"{aho:<18.6f}"
        f"{speedup:<15.2f}x"
    )




# ---------------------------------
# Export Benchmark Results to CSV
# ---------------------------------
benchmark_results_df = pd.DataFrame({
    "input_size_chars": text_lengths,
    "naive_time_seconds": naive_times,
    "aho_corasick_time_seconds": aho_times,
    "speedup_factor": [n/a if a > 0 else float("inf") for n, a in zip(naive_times, aho_times)]
})

benchmark_results_df.to_csv("throughput_benchmark_results.csv", index=False)
print(f"\n[SUCCESS] Benchmark results exported to 'throughput_benchmark_results.csv'")
print(benchmark_results_df.to_string(index=False))

# ------------------
# Plot Graph
# ------------------

plt.figure(figsize=(10,6))

plt.plot(
    text_lengths,
    naive_times,
    marker="o",
    linestyle="--",
    linewidth=2,
    label="Naive String Matching (O(N × M))"
)

plt.plot(
    text_lengths,
    aho_times,
    marker="s",
    linewidth=2,
    label="Aho-Corasick (O(N + M + Z))"
)

plt.title("Performance Comparison: Aho-Corasick vs Naive String Matching")

plt.xlabel("Input Text Length (Characters)")

plt.ylabel("Average Execution Time (Seconds)")

plt.grid(True)

plt.legend()

plt.tight_layout()

plt.savefig("benchmark_results.png", dpi=300, bbox_inches="tight")

plt.show()

print("\n[SUCCESS] Benchmark graph exported as 'benchmark_results.png'")






# ===========================================================================
# Phase 6: Security Evaluation (False Negative Rate / False Positive Rate)
# ============================================================================

print("\n" + "="*60)
print("PHASE 6: Security Evaluation - FNR / FPR Analysis")
print("="*60)

# ------------------------------------------------------------------
# Load a Benign Log Corpus (Local Priority with Fallback)
# ------------------------------------------------------------------
# need a set of KNOWN-SAFE log lines to test for false positives.
# I found Loghub's OpenSSH dataset is a standard, citable benchmark of benign
# system logs, widely used in log-analysis research.

benign_logs = []

try:
    # 1st Priority: Local file if already downloaded
    with open("openssh_benign_logs.txt", "r", encoding="utf-8") as f:
        benign_logs = [line.strip() for line in f.readlines() if line.strip()]
    print(f"[+] Loaded {len(benign_logs)} benign log lines from local file.")

except FileNotFoundError:
    # 2nd Priority: Fallback to Loghub's raw GitHub sample
    loghub_url = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
    try:
        print("[*] Local benign log file not found. Fetching from Loghub (GitHub)...")
        response = urllib.request.urlopen(loghub_url)
        raw_text = response.read().decode('utf-8', errors='ignore')
        benign_logs = [line.strip() for line in raw_text.split('\n') if line.strip()]
        print(f"[+] Loaded {len(benign_logs)} benign log lines from Loghub GitHub.")
    except urllib.error.URLError as e:
        print(f"[-] Could not reach Loghub ({e.reason}). Using a small fallback benign sample.")
        # 3rd Priority: Minimal built-in fallback so the script never crashes
        benign_logs = [
            "Accepted password for user1 from 192.168.1.5 port 22 ssh2",
            "Connection closed by 192.168.1.10 port 51422",
            "session opened for user admin by (uid=0)",
            "Failed password for invalid user test from 10.0.0.5 port 44212 ssh2",
            "Received disconnect from 192.168.1.20: 11: disconnected by user",
        ]

print(f"[SUCCESS] Benign log corpus ready: {len(benign_logs)} lines.")


# ------------------------------------------------------------------
# Run Aho-Corasick Against the MALICIOUS Set (Recall / FNR)
# ------------------------------------------------------------------
# For every known-malicious payload, check whether the engine detects it
# when embedded in a realistic log-style sentence.

print("\n[*] Evaluating detection rate on malicious payload set...")

true_positives = 0
false_negatives = 0
missed_payloads = []

for payload in cmdi_signatures:
    # Wrap the payload in a small log-like context, similar to real usage
    test_line = f"user_input: {payload}"
    matches = waf_engine.search(test_line)

    if matches:
        true_positives += 1
    else:
        false_negatives += 1
        missed_payloads.append(payload)

total_malicious = len(cmdi_signatures)
recall = true_positives / total_malicious if total_malicious > 0 else 0
false_negative_rate = false_negatives / total_malicious if total_malicious > 0 else 0

print(f"[+] Total malicious payloads tested: {total_malicious}")
print(f"[+] True Positives (correctly flagged): {true_positives}")
print(f"[+] False Negatives (missed): {false_negatives}")
print(f"[+] Recall (Detection Rate): {recall:.4f} ({recall*100:.2f}%)")
print(f"[+] False Negative Rate: {false_negative_rate:.4f} ({false_negative_rate*100:.2f}%)")

# ------------------------------------------------------------------
#Run Aho-Corasick Against the BENIGN Set (Specificity / FPR)
# ------------------------------------------------------------------
# For every known-safe log line, check whether the engine incorrectly
# flags it as malicious.

print("\n[*] Evaluating false positive rate on benign log set...")

true_negatives = 0
false_positives = 0
false_positive_lines = []

for line in benign_logs:
    matches = waf_engine.search(line)

    if matches:
        false_positives += 1
        false_positive_lines.append((line, matches))
    else:
        true_negatives += 1

total_benign = len(benign_logs)
specificity = true_negatives / total_benign if total_benign > 0 else 0
false_positive_rate = false_positives / total_benign if total_benign > 0 else 0

print(f"[+] Total benign log lines tested: {total_benign}")
print(f"[+] True Negatives (correctly passed): {true_negatives}")
print(f"[+] False Positives (incorrectly flagged): {false_positives}")
print(f"[+] Specificity: {specificity:.4f} ({specificity*100:.2f}%)")
print(f"[+] False Positive Rate: {false_positive_rate:.4f} ({false_positive_rate*100:.2f}%)")

# -----------------------------
# Summary Table
# ----------------------------

print("\n" + "="*60)
print("SECURITY EVALUATION SUMMARY")
print("="*60)
print(f"{'Metric':<30}{'Value':<15}")
print("-"*45)
print(f"{'Recall (Detection Rate)':<30}{recall*100:.2f}%")
print(f"{'False Negative Rate':<30}{false_negative_rate*100:.2f}%")
print(f"{'Specificity':<30}{specificity*100:.2f}%")
print(f"{'False Positive Rate':<30}{false_positive_rate*100:.2f}%")
print("="*60)

if missed_payloads:
    print(f"\n[NOTE] Sample of missed payloads (first 3): {missed_payloads[:3]}")
if false_positive_lines:
    print(f"[NOTE] Sample false positive (first 1): {false_positive_lines[:1]}")




