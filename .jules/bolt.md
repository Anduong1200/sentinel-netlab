## 2024-05-24 - O(N) complexity bug in `audit_network` from re-calculating sets in loops
**Learning:** In `sensor/auditor/engine.py`, recreating `existing_ids = {f.id for f in self.findings}` inside the `audit_network` loop caused O(N) linear time per network added. As the number of accumulated findings (N) grew, auditing M networks took O(N*M) time, degrading performance severely.
**Action:** Replaced the in-loop set recreation with an O(1) class-level attribute (`self._finding_ids`) that is updated whenever a finding is added to `self.findings`, successfully resolving the complexity issue and resulting in 10x+ speedups for large scans.

## 2026-03-20 - O(N) complexity bug in `generate_report_data` from `list.index()` during sort
**Learning:** In `sensor/auditor/engine.py`, the `generate_report_data` method sorted `self.findings` using `severity_order.index(f.severity)` as the lambda sort key. For a list of N findings and M severity levels, this makes the comparison operation O(M), bringing the sorting time up to O(M * N log N), which can become a bottleneck when N is large.
**Action:** Always prefer O(1) dictionary lookups for sort rank keys instead of dynamically invoking `list.index()`. By computing a `severity_map = {s: i for i, s in enumerate(severity_order)}` before sorting and using `severity_map.get(f.severity)`, we reduce sort complexity strictly back to O(N log N).

## 2026-03-30 - O(N) complexity bug in sliding time-windows and array eviction via `pop(0)`
**Learning:** High-frequency event ingestion loops using bounded sliding windows stored as lists with `.pop(0)` suffer from extreme O(N) reallocation latency as elements stack. This was observed in `algos/pmkid_detector.py`'s manual timestamp eviction and `algos/jamming_detector.py`'s manual `rssi_samples` array limit.
**Action:** Always replace `pop(0)` list evictions. For chronological sorting bounds, use `bisect.bisect_left` paired with slice deletion (`del array[:idx]`). For pure maximum-length eviction strategies (fixed bounding size arrays), use `collections.deque(maxlen=K)` for guaranteed O(1) removals.
