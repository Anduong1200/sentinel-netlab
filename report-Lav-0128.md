# Sentinel NetLab - Update Report (Lav-0128)

This report summarizes all the changes, bug fixes, and improvements made to the Sentinel NetLab project since the repository was pulled.

## 1. TUI (Control Panel) Enhancements & Bug Fixes

*   **Fixed Input Text Visibility (Fix 1):**
    *   **File:** `sensor/tui/theme.tcss`
    *   **Issue:** Typed text in `Input` widgets was invisible due to conflicting background and text colors.
    *   **Solution:** Added explicit CSS rules (`Input:focus`, `.input--placeholder`, `.input--cursor`) to apply a blue highlight border (`#58a6ff`) on focus and ensure high contrast for text and cursors against the dark background.

*   **Fixed Controller Online Status Check (Fix 2):**
    *   **File:** `sensor/tui/app.py`
    *   **Issue:** The setup screen incorrectly reported the controller as "OFFLINE" because the health check probed an authenticated endpoint (`/api/v1/sensors`) with a very short 1-second timeout.
    *   **Solution:** Switched the probe endpoint to the unauthenticated `/api/v1/health` route and increased the timeout to 2 seconds, ensuring accurate backend status reporting.

*   **Added WLAN Interface Picker (Fix 3):**
    *   **File:** `sensor/tui/app.py`
    *   **Issue:** Users had to manually type the network interface name (e.g., `wlan0mon`), which was prone to typos.
    *   **Solution:** Replaced the plain text input with a robust `Select` dropdown widget. The list is automatically populated with system network interfaces using `detect_wifi_interfaces()`, prioritizing those in monitor mode. A manual fallback `Input` was retained just below the dropdown for custom entries.

*   **Improved Key Generation UX (Fix 4):**
    *   **File:** `sensor/tui/app.py`
    *   **Issue:** Clicking the "Gen Token/Keys" button provided little feedback on what was actually generated.
    *   **Solution:** Upgraded the status message to clearly show the token source (API vs. local). It now displays a masked preview of the generated token (e.g., `abcdef…wxyz`) and reports the exact number of keys written to the `.env` file.

*   **Added Dashboard Status Banner (Fix 5):**
    *   **Files:** `sensor/tui/app.py`, `sensor/tui/theme.tcss`
    *   **Issue:** When switching to the Dashboard, it wasn't immediately clear if the sensor agent had successfully started.
    *   **Solution:** Implemented a highly visible status banner beneath the header. It displays a green `● SENSOR ACTIVE` label (with mode, interface, ID, and uptime) when running, or a yellow `○ SENSOR IDLE` label when waiting.

## 2. Documentation Cleanup

*   **File:** `README.md`
*   **Changes:**
    *   Cleaned up duplicate and malformed HTML `<p>` tags at the top of the document.
    *   Added a dedicated **TUI Control Panel** section featuring a capability table and workflow guide for new users.
    *   Properly integrated the "Known Limitations" section into the document hierarchy, highlighting OS constraints (Windows/macOS vs. Linux).
    *   Polished the Docker deployment instructions, clarifying the use of `--env-file` for lab and production setups.

## 3. Testing and Environment Setup

*   **Dependency Resolution:** Installed missing local packages (`pyyaml`, `textual`, `psutil`) and project dev dependencies (`pip install -e ".[dev]"`) to ensure the TUI and test suite can run smoothly on the host machine.
*   **Test Suite Updates:** Updated the `test_tui_app_setup.py` scripts to be fully compatible with the newly introduced `Select` widget for interface picking.
*   **Test Results:** Successfully ran the complete `pytest` suite. **100% Passed (28/28 tests)** across `Setup Wizard`, `TUI State`, and `App Setup` modules in ~16 seconds.

---
The TUI is now fully functional and stable. It can be launched from the project root using:
```bash
python -m sensor.tui
```
