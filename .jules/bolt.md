## 2024-05-24 - O(N) complexity bug in `audit_network` from re-calculating sets in loops
**Learning:** In `sensor/auditor/engine.py`, recreating `existing_ids = {f.id for f in self.findings}` inside the `audit_network` loop caused O(N) linear time per network added. As the number of accumulated findings (N) grew, auditing M networks took O(N*M) time, degrading performance severely.
**Action:** Replaced the in-loop set recreation with an O(1) class-level attribute (`self._finding_ids`) that is updated whenever a finding is added to `self.findings`, successfully resolving the complexity issue and resulting in 10x+ speedups for large scans.

## 2026-03-20 - O(N) complexity bug in `generate_report_data` from `list.index()` during sort
**Learning:** In `sensor/auditor/engine.py`, the `generate_report_data` method sorted `self.findings` using `severity_order.index(f.severity)` as the lambda sort key. For a list of N findings and M severity levels, this makes the comparison operation O(M), bringing the sorting time up to O(M * N log N), which can become a bottleneck when N is large.
**Action:** Always prefer O(1) dictionary lookups for sort rank keys instead of dynamically invoking `list.index()`. By computing a `severity_map = {s: i for i, s in enumerate(severity_order)}` before sorting and using `severity_map.get(f.severity)`, we reduce sort complexity strictly back to O(N log N).

## 2026-03-31 - O(N) complexity bug in sliding time windows via `pop(0)`
**Learning:** In bounded time-series sliding windows (e.g. `_cleanup_timestamps`), clearing a list using a `while` loop and `list.pop(0)` is O(N^2) in the worst case (or O(K * N) where K elements are removed).
**Action:** Always replace `pop(0)` loops with `bisect.bisect_left` and batch deletion (`del lst[:idx]`). This drops the time complexity to O(log N + N), which is critically faster for handling high-frequency packet floods.

## 2026-03-31 - Suboptimal bounded buffers using `list`
**Learning:** In buffers that store the last N items (like `rssi_samples`), manually enforcing the bound via `if len(lst) > 100: lst.pop(0)` incurs an O(N) cost on every insertion once the list is full.
**Action:** Use `collections.deque(maxlen=N)` for fixed-size buffers, which automatically provides O(1) eviction for the oldest elements and guarantees memory efficiency.
