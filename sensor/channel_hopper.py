import logging
import random
import threading
import time

from sensor.capture_driver import CaptureDriver

logger = logging.getLogger(__name__)


class ChannelHopper:
    """
    Manages channel hopping with configurable dwell time.
    Supports adaptive channel selection based on activity.
    """

    def __init__(
        self,
        driver: CaptureDriver,
        channels: list[int] | None = None,
        dwell_ms: int = 200,
        settle_ms: int = 50,
        adaptive: bool = False,
    ):
        self.driver = driver
        # Default 2.4GHz non-overlapping
        self.channels = channels or [1, 6, 11]
        self.dwell_ms = dwell_ms
        self.settle_ms = settle_ms
        self.adaptive = adaptive

        self._current_idx = 0
        self._running = False
        self._thread: threading.Thread | None = None
        self._channel_activity: dict[int, float] = dict.fromkeys(self.channels, 1.0)

    def start(self) -> None:
        """Start channel hopping thread"""
        self._running = True
        self._thread = threading.Thread(
            target=self._hop_loop, daemon=True, name="ChannelHopper"
        )
        self._thread.start()
        logger.info(
            f"Channel hopping started: {self.channels}, dwell={self.dwell_ms}ms"
        )

    def stop(self) -> None:
        """Stop channel hopping"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def get_current_channel(self) -> int:
        """Get current channel"""
        if self._current_idx < len(self.channels):
            return self.channels[self._current_idx]
        return 0

    def record_activity(self, channel: int, count: int) -> None:
        """Record frame activity on channel for adaptive mode"""
        if channel in self._channel_activity:
            # Exponential moving average
            alpha = 0.3
            self._channel_activity[channel] = (
                alpha * count + (1 - alpha) * self._channel_activity[channel]
            )

    def _hop_loop(self) -> None:
        """Main hopping loop"""
        while self._running:
            try:
                # Select next channel
                if self.adaptive:
                    channel = self._select_adaptive()
                else:
                    channel = self._select_round_robin()

                # Switch channel
                if self.driver.set_channel(channel):
                    time.sleep(self.settle_ms / 1000.0)

                # Dwell
                time.sleep(self.dwell_ms / 1000.0)

            except Exception as e:
                logger.error(f"Channel hop error: {e}")
                time.sleep(1)

    def _select_round_robin(self) -> int:
        """Simple round-robin selection"""
        self._current_idx = (self._current_idx + 1) % len(self.channels)
        return self.channels[self._current_idx]

    def _select_adaptive(self) -> int:
        """Select channel weighted by activity"""
        total = sum(self._channel_activity.values())
        r = random.random() * total  # noqa: S311
        cumulative: float = 0.0
        for ch in self.channels:
            cumulative += self._channel_activity[ch]
            if r <= cumulative:
                return ch
        return self.channels[0]
