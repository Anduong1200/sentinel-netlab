#!/usr/bin/env python3
"""
Producer-Consumer Capture Engine
High-performance packet capture using multiprocessing queue.
Separates capture (fast) from processing (slow) to prevent packet loss.
"""

import logging
import multiprocessing as mp
import queue
import subprocess  # nosec B404
import threading
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class CaptureProducer(mp.Process):
    """
    Producer process: Captures packets using dumpcap/tshark and pushes to queue.
    Runs in separate process to avoid GIL issues.
    """

    def __init__(
        self,
        packet_queue: mp.Queue,
        interface: str,
        channels: list[int],
        stop_event: mp.Event,
        dwell_time: float = 0.5,
    ):
        super().__init__(daemon=True)
        self.packet_queue = packet_queue
        self.interface = interface
        self.channels = channels
        self.stop_event = stop_event
        self.dwell_time = dwell_time
        self.capture_process = None

    def enable_monitor_mode(self):
        """Enable monitor mode."""
        try:
            subprocess.run(
                ["ip", "link", "set", self.interface, "down"], check=True, timeout=5
            )
            subprocess.run(
                ["iw", "dev", self.interface, "set", "type", "monitor"],
                check=True,
                timeout=5,
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"], check=True, timeout=5
            )
            return True
        except Exception as e:
            logger.error(f"Monitor mode failed: {e}")
            return False

    def set_channel(self, channel: int):
        """Set wireless channel."""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                timeout=2,
                capture_output=True,
            )
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            pass

    def run(self):
        """Main producer loop."""
        logger.info(f"Producer started on {self.interface}")
        self.enable_monitor_mode()

        # Start dumpcap for high-performance capture
        # -i: interface, -P: pcapng format, -w -: output to stdout
        # -f: BPF filter
        cmd = [
            "dumpcap",
            "-i",
            self.interface,
            "-P",  # pcapng
            "-w",
            "-",  # stdout
            "-f",
            "type mgt or ether proto 0x888e",
            "-q",
        ]

        try:
            self.capture_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            # Fallback to tshark
            cmd = [
                "tshark",
                "-i",
                self.interface,
                "-T",
                "ek",  # Elastic/JSON format for streaming
                "-l",  # Line buffered
                "-f",
                "type mgt or ether proto 0x888e",
            ]
            self.capture_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )

        # Channel hopper thread
        channel_idx = 0
        last_hop = time.time()

        while not self.stop_event.is_set():
            # Channel hopping
            if time.time() - last_hop >= self.dwell_time:
                channel = self.channels[channel_idx % len(self.channels)]
                self.set_channel(channel)
                channel_idx += 1
                last_hop = time.time()

            # Read from capture process
            try:
                line = self.capture_process.stdout.readline()
                if line:
                    try:
                        # Push to queue (non-blocking)
                        self.packet_queue.put_nowait(
                            {
                                "timestamp": time.time(),
                                "data": line.strip() if isinstance(line, str) else line,
                                "channel": self.channels[
                                    (channel_idx - 1) % len(self.channels)
                                ],
                            }
                        )
                    except queue.Full:
                        # Queue full, drop oldest
                        try:
                            self.packet_queue.get_nowait()
                            self.packet_queue.put_nowait(
                                {
                                    "timestamp": time.time(),
                                    "data": (
                                        line.strip() if isinstance(line, str) else line
                                    ),
                                    "channel": self.channels[
                                        (channel_idx - 1) % len(self.channels)
                                    ],
                                }
                            )
                        except (queue.Full, queue.Empty):
                            pass
            except OSError:
                time.sleep(0.01)

        # Cleanup
        if self.capture_process:
            self.capture_process.terminate()

        logger.info("Producer stopped")


class CaptureConsumer(threading.Thread):
    """
    Consumer thread: Processes packets from queue and invokes callbacks.
    Runs in main process.
    """

    def __init__(
        self,
        packet_queue: mp.Queue,
        stop_event: mp.Event,
        packet_callback: Callable | None = None,
        batch_size: int = 50,
        batch_timeout: float = 1.0,
    ):
        super().__init__(daemon=True)
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.packet_callback = packet_callback
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout

        self.stats = {
            "packets_processed": 0,
            "batches_processed": 0,
            "queue_max_size": 0,
        }

    def run(self):
        """Main consumer loop."""
        logger.info("Consumer started")
        batch = []
        last_flush = time.time()

        while not self.stop_event.is_set():
            try:
                # Get packet with timeout
                pkt = self.packet_queue.get(timeout=0.1)
                batch.append(pkt)

                # Track queue size
                qsize = self.packet_queue.qsize()
                if qsize > self.stats["queue_max_size"]:
                    self.stats["queue_max_size"] = qsize

                # Process batch when full or timeout
                if (
                    len(batch) >= self.batch_size
                    or (time.time() - last_flush) >= self.batch_timeout
                ):
                    self._process_batch(batch)
                    batch = []
                    last_flush = time.time()

            except queue.Empty:
                # Flush remaining batch on timeout
                if batch and (time.time() - last_flush) >= self.batch_timeout:
                    self._process_batch(batch)
                    batch = []
                    last_flush = time.time()

        # Final flush
        if batch:
            self._process_batch(batch)

        logger.info(f"Consumer stopped. Stats: {self.stats}")

    def _process_batch(self, batch: list[dict]):
        """Process a batch of packets."""
        for pkt in batch:
            try:
                if self.packet_callback:
                    self.packet_callback(pkt)
                self.stats["packets_processed"] += 1
            except Exception as e:
                logger.debug(f"Packet processing error: {e}")

        self.stats["batches_processed"] += 1


class ProducerConsumerEngine:
    """
    Main engine combining Producer and Consumer.
    """

    def __init__(
        self,
        interface: str = "wlan0",
        queue_size: int = 10000,
        channels: list[int] | None = None,
    ):
        self.interface = interface
        self.queue_size = queue_size
        self.channels = channels or [1, 6, 11]

        self.packet_queue: mp.Queue | None = None
        self.stop_event: mp.Event | None = None
        self.producer: CaptureProducer | None = None
        self.consumer: CaptureConsumer | None = None

        self.is_capturing = False

    def start(self, packet_callback: Callable | None = None) -> bool:
        """Start capture engine."""
        if self.is_capturing:
            return False

        # Create IPC primitives
        self.packet_queue = mp.Queue(maxsize=self.queue_size)
        self.stop_event = mp.Event()

        # Start producer (separate process)
        self.producer = CaptureProducer(
            packet_queue=self.packet_queue,
            interface=self.interface,
            channels=self.channels,
            stop_event=self.stop_event,
        )
        self.producer.start()

        # Start consumer (thread in main process)
        self.consumer = CaptureConsumer(
            packet_queue=self.packet_queue,
            stop_event=self.stop_event,
            packet_callback=packet_callback,
        )
        self.consumer.start()

        self.is_capturing = True
        logger.info("Producer-Consumer engine started")
        return True

    def stop(self):
        """Stop capture engine."""
        if not self.is_capturing:
            return

        self.stop_event.set()

        if self.producer:
            self.producer.join(timeout=5)
            if self.producer.is_alive():
                self.producer.terminate()

        if self.consumer:
            self.consumer.join(timeout=5)

        self.is_capturing = False
        logger.info("Producer-Consumer engine stopped")

    def get_status(self) -> dict[str, Any]:
        """Get engine status."""
        return {
            "engine": "producer-consumer",
            "interface": self.interface,
            "is_capturing": self.is_capturing,
            "channels": self.channels,
            "queue_size": self.packet_queue.qsize() if self.packet_queue else 0,
            "queue_capacity": self.queue_size,
            "consumer_stats": self.consumer.stats if self.consumer else {},
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Producer-Consumer Capture Engine")
    parser.add_argument("-i", "--interface", default="wlan0")
    parser.add_argument("-c", "--channels", default="1,6,11")
    parser.add_argument("-t", "--duration", type=int, default=30)
    parser.add_argument("-q", "--queue-size", type=int, default=10000)

    args = parser.parse_args()

    print("=" * 50)
    print("Producer-Consumer Capture Engine")
    print("=" * 50)

    channels = [int(c) for c in args.channels.split(",")]
    packet_count = {"value": 0}

    def on_packet(pkt):
        packet_count["value"] += 1
        if packet_count["value"] % 100 == 0:
            print(f"Processed {packet_count['value']} packets")

    engine = ProducerConsumerEngine(
        interface=args.interface, queue_size=args.queue_size, channels=channels
    )

    print(f"Interface: {args.interface}")
    print(f"Channels: {channels}")
    print(f"Duration: {args.duration}s")
    print("-" * 50)

    engine.start(packet_callback=on_packet)

    try:
        for i in range(args.duration):
            time.sleep(1)
            status = engine.get_status()
            print(
                f"[{i + 1}s] Queue: {status['queue_size']}/{status['queue_capacity']}"
            )
    except KeyboardInterrupt:
        pass

    engine.stop()
    print(f"\nTotal packets: {packet_count['value']}")
