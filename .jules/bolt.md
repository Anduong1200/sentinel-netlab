## 2024-05-24 - O(N) complexity bug in `audit_network` from re-calculating sets in loops
**Learning:** In `sensor/auditor/engine.py`, recreating `existing_ids = {f.id for f in self.findings}` inside the `audit_network` loop caused O(N) linear time per network added. As the number of accumulated findings (N) grew, auditing M networks took O(N*M) time, degrading performance severely.
**Action:** Replaced the in-loop set recreation with an O(1) class-level attribute (`self._finding_ids`) that is updated whenever a finding is added to `self.findings`, successfully resolving the complexity issue and resulting in 10x+ speedups for large scans.

## 2026-03-20 - O(N) complexity bug in `generate_report_data` from `list.index()` during sort
**Learning:** In `sensor/auditor/engine.py`, the `generate_report_data` method sorted `self.findings` using `severity_order.index(f.severity)` as the lambda sort key. For a list of N findings and M severity levels, this makes the comparison operation O(M), bringing the sorting time up to O(M * N log N), which can become a bottleneck when N is large.
**Action:** Always prefer O(1) dictionary lookups for sort rank keys instead of dynamically invoking `list.index()`. By computing a `severity_map = {s: i for i, s in enumerate(severity_order)}` before sorting and using `severity_map.get(f.severity)`, we reduce sort complexity strictly back to O(N log N).

## 2026-10-24 - O(N) bottleneck in `list.pop(0)` for sliding windows and bounded lists
**Learning:** In `algos/pmkid_detector.py` and `algos/jamming_detector.py`, using `list.pop(0)` to evict old elements from time-windows/bounded lists causes an O(N) memory shift per eviction. In high-frequency sensor loops, multiple explicit `pop(0)` operations per frame dramatically degrade performance.
**Action:** Replace `pop(0)` in explicit loops with O(log N) `bisect.bisect_left` followed by a single O(N) batch slice deletion (`del lst[:idx]`). For bounded history that does not require slicing or binary search (e.g. RSSI averaging), replace `list` with O(1) `collections.deque(maxlen=K)`.
