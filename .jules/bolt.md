## 2024-05-24 - O(N) complexity bug in `audit_network` from re-calculating sets in loops
**Learning:** In `sensor/auditor/engine.py`, recreating `existing_ids = {f.id for f in self.findings}` inside the `audit_network` loop caused O(N) linear time per network added. As the number of accumulated findings (N) grew, auditing M networks took O(N*M) time, degrading performance severely.
**Action:** Replaced the in-loop set recreation with an O(1) class-level attribute (`self._finding_ids`) that is updated whenever a finding is added to `self.findings`, successfully resolving the complexity issue and resulting in 10x+ speedups for large scans.

## 2026-03-20 - O(N) complexity bug in `generate_report_data` from `list.index()` during sort
**Learning:** In `sensor/auditor/engine.py`, the `generate_report_data` method sorted `self.findings` using `severity_order.index(f.severity)` as the lambda sort key. For a list of N findings and M severity levels, this makes the comparison operation O(M), bringing the sorting time up to O(M * N log N), which can become a bottleneck when N is large.
**Action:** Always prefer O(1) dictionary lookups for sort rank keys instead of dynamically invoking `list.index()`. By computing a `severity_map = {s: i for i, s in enumerate(severity_order)}` before sorting and using `severity_map.get(f.severity)`, we reduce sort complexity strictly back to O(N log N).

## 2027-03-27 - O(N) complexity bug in `JammingDetector` from `list.pop(0)` for sliding window
**Learning:** In `algos/jamming_detector.py`, the `JammingDetector.ingest` method used `list.pop(0)` to maintain a bounded sliding window of 100 `rssi_samples`. Since `list.pop(0)` is an O(N) operation in Python, calling it repeatedly on a high-frequency per-packet ingestion loop introduces unnecessary overhead.
**Action:** Replace bounded list manipulations with `collections.deque(maxlen=K)`. The `deque` structure inherently manages the bounded size and automatically drops the oldest elements in O(1) time when adding new elements.
