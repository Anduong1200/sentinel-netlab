"""Distributed geo-location enrichment service for controller APIs."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable

from controller.config import GeoConfig

logger = logging.getLogger(__name__)

DEFAULT_FREQUENCY_MHZ = 2412
EARTH_RADIUS_M = 6378137.0


@dataclass
class _SensorReading:
    sensor_id: str
    rssi_dbm: float
    timestamp: datetime
    frequency_mhz: int


def _coerce_datetime(value: Any) -> datetime | None:
    """Best-effort conversion to timezone-aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        iso = value.strip()
        if not iso:
            return None
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(iso)
        except ValueError:
            return None
    else:
        return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class DistributedGeoService:
    """Enrich network observations with distributed geo-location metadata."""

    def __init__(self, geo_config: GeoConfig):
        self.geo_config = geo_config
        self.enabled = bool(geo_config and geo_config.enabled)
        self._geo_mapper = None
        self._rssi_sample_cls = None

        if self.enabled:
            self._init_mapper()

    def _init_mapper(self) -> None:
        """Initialize GeoMapper and register known controller sensor positions."""
        try:
            from sensor.geo_mapping import GeoMapper, RSSISample
        except ImportError as e:
            logger.warning(
                "Geo enabled but GeoMapper dependencies are unavailable: %s", e
            )
            return

        self._geo_mapper = GeoMapper(environment="indoor_los")
        self._rssi_sample_cls = RSSISample

        for sensor_id, pos in self.geo_config.sensor_positions.items():
            self._geo_mapper.register_sensor(
                sensor_id=sensor_id,
                x=float(pos["x"]),
                y=float(pos["y"]),
                z=float(pos.get("z", 0.0)),
            )

    def estimate_by_bssid(
        self, telemetry_records: Iterable[Any]
    ) -> dict[str, dict[str, Any]]:
        """Estimate geo-position per BSSID from recent telemetry records."""
        if not self.enabled:
            return {}

        cutoff = datetime.now(UTC) - timedelta(seconds=self.geo_config.sample_window_sec)

        grouped: dict[str, dict[str, _SensorReading]] = defaultdict(dict)
        for record in telemetry_records:
            data = getattr(record, "data", None)
            if not isinstance(data, dict):
                continue

            bssid = data.get("bssid")
            if not bssid:
                continue

            sensor_id = data.get("sensor_id") or getattr(record, "sensor_id", None)
            if not sensor_id or sensor_id not in self.geo_config.sensor_positions:
                continue

            rssi = data.get("rssi_dbm")
            if rssi is None:
                continue

            try:
                rssi_dbm = float(rssi)
            except (TypeError, ValueError):
                continue

            timestamp = (
                _coerce_datetime(data.get("timestamp_utc"))
                or _coerce_datetime(data.get("timestamp"))
                or _coerce_datetime(getattr(record, "timestamp", None))
                or _coerce_datetime(getattr(record, "ingested_at", None))
                or datetime.now(UTC)
            )

            if timestamp < cutoff:
                continue

            frequency = data.get("frequency_mhz") or getattr(record, "frequency_mhz", None)
            try:
                frequency_mhz = int(frequency) if frequency is not None else DEFAULT_FREQUENCY_MHZ
            except (TypeError, ValueError):
                frequency_mhz = DEFAULT_FREQUENCY_MHZ

            current = grouped[bssid].get(sensor_id)
            if current is None or timestamp >= current.timestamp:
                grouped[bssid][sensor_id] = _SensorReading(
                    sensor_id=sensor_id,
                    rssi_dbm=rssi_dbm,
                    timestamp=timestamp,
                    frequency_mhz=frequency_mhz,
                )

        results: dict[str, dict[str, Any]] = {}
        for bssid, reading_map in grouped.items():
            estimate = self._estimate_single_bssid(bssid, reading_map)
            if estimate:
                results[bssid] = estimate

        return results

    def _estimate_single_bssid(
        self, bssid: str, reading_map: dict[str, _SensorReading]
    ) -> dict[str, Any] | None:
        if not reading_map:
            return None

        source_sensor_ids = sorted(reading_map.keys())
        sample_sensor_count = len(source_sensor_ids)

        if (
            sample_sensor_count >= 3
            and self._geo_mapper is not None
            and self._rssi_sample_cls is not None
        ):
            samples = [
                self._rssi_sample_cls(
                    sensor_id=reading.sensor_id,
                    bssid=bssid,
                    rssi_dbm=reading.rssi_dbm,
                    timestamp_utc=reading.timestamp.isoformat(),
                    frequency_mhz=reading.frequency_mhz,
                )
                for reading in reading_map.values()
            ]

            estimate = self._geo_mapper.process_samples(samples)
            if estimate is not None:
                return self._pack_result(
                    method=estimate.method,
                    x_m=float(estimate.x),
                    y_m=float(estimate.y),
                    confidence=float(estimate.confidence),
                    error_radius_m=float(estimate.error_radius_m),
                    sample_sensor_count=sample_sensor_count,
                    source_sensor_ids=source_sensor_ids,
                )

        strongest = max(reading_map.values(), key=lambda item: item.rssi_dbm)
        sensor_pos = self.geo_config.sensor_positions[strongest.sensor_id]
        x_m = float(sensor_pos["x"])
        y_m = float(sensor_pos["y"])

        normalized = self._normalize_rssi(strongest.rssi_dbm)
        confidence = 0.2 + (normalized * 0.45)
        error_radius_m = 8.0 + ((1.0 - normalized) * 20.0)

        return self._pack_result(
            method="strongest_rssi",
            x_m=x_m,
            y_m=y_m,
            confidence=confidence,
            error_radius_m=error_radius_m,
            sample_sensor_count=sample_sensor_count,
            source_sensor_ids=source_sensor_ids,
        )

    def _pack_result(
        self,
        method: str,
        x_m: float,
        y_m: float,
        confidence: float,
        error_radius_m: float,
        sample_sensor_count: int,
        source_sensor_ids: list[str],
    ) -> dict[str, Any]:
        lat, lon = self._xy_to_lat_lon(x_m, y_m)
        return {
            "lat": lat,
            "lon": lon,
            "geo": {
                "method": method,
                "x_m": round(x_m, 3),
                "y_m": round(y_m, 3),
                "confidence": round(confidence, 4),
                "error_radius_m": round(error_radius_m, 3),
                "sample_sensor_count": sample_sensor_count,
                "source_sensor_ids": source_sensor_ids,
            },
        }

    def _xy_to_lat_lon(self, x_m: float, y_m: float) -> tuple[float | None, float | None]:
        if self.geo_config.origin_lat is None or self.geo_config.origin_lon is None:
            return None, None

        lat0_rad = math.radians(self.geo_config.origin_lat)
        cos_lat0 = math.cos(lat0_rad)
        if abs(cos_lat0) < 1e-12:
            return None, None

        lat = self.geo_config.origin_lat + (y_m / EARTH_RADIUS_M) * (180.0 / math.pi)
        lon = self.geo_config.origin_lon + (x_m / (EARTH_RADIUS_M * cos_lat0)) * (
            180.0 / math.pi
        )
        return round(lat, 8), round(lon, 8)

    @staticmethod
    def _normalize_rssi(rssi_dbm: float) -> float:
        """Normalize RSSI into [0, 1], where 1 means strongest signal."""
        clamped = max(-90.0, min(-30.0, rssi_dbm))
        return (clamped + 90.0) / 60.0
