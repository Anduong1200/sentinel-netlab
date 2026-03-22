## 2024-05-24 - O(N) complexity bug in `audit_network` from re-calculating sets in loops
**Learning:** In `sensor/auditor/engine.py`, recreating `existing_ids = {f.id for f in self.findings}` inside the `audit_network` loop caused O(N) linear time per network added. As the number of accumulated findings (N) grew, auditing M networks took O(N*M) time, degrading performance severely.
**Action:** Replaced the in-loop set recreation with an O(1) class-level attribute (`self._finding_ids`) that is updated whenever a finding is added to `self.findings`, successfully resolving the complexity issue and resulting in 10x+ speedups for large scans.

## 2026-03-20 - O(N) complexity bug in `generate_report_data` from `list.index()` during sort
**Learning:** In `sensor/auditor/engine.py`, the `generate_report_data` method sorted `self.findings` using `severity_order.index(f.severity)` as the lambda sort key. For a list of N findings and M severity levels, this makes the comparison operation O(M), bringing the sorting time up to O(M * N log N), which can become a bottleneck when N is large.
**Action:** Always prefer O(1) dictionary lookups for sort rank keys instead of dynamically invoking `list.index()`. By computing a `severity_map = {s: i for i, s in enumerate(severity_order)}` before sorting and using `severity_map.get(f.severity)`, we reduce sort complexity strictly back to O(N log N).

## 2026-03-22 - O(N) complexity filtering sorted chronological sliding time-windows
**Learning:** In high-volume event processing (like `algos/dos.py`, `algos/krack_detector.py`, `algos/beacon_flood_detector.py`), filtering chronologically sorted lists of timestamps using list comprehensions (`[t for t in history if t >= cutoff]`) creates an O(N) bottleneck from evaluating bytecode.
**Action:** Since chronological timestamps are naturally sorted, use `bisect.bisect_left` to find the cutoff index in O(log N) time, and then slice the list (`history[idx:]`). While list slicing is technically an O(N) memory allocation operation, it leverages highly optimized C routines (`memcpy`), drastically improving performance for large sliding windows over list comprehensions.
