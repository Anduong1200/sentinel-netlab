#!/usr/bin/env python3
"""
Sentinel NetLab - Geo-Mapping Module
Multi-sensor sync, trilateration, and heatmap generation.

Implements:
- NTP-based sensor time synchronization
- Log-distance path loss model for RSSI → distance
- Trilateration solver for position estimation
- Kalman filter for noise reduction
- Heatmap export (PNG/SVG)
"""

import math
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class SensorPosition:
    """Known position of a sensor"""
    sensor_id: str
    x: float  # meters
    y: float  # meters
    z: float = 0.0  # meters (height)
    ntp_offset_ms: float = 0.0  # Clock offset from reference


@dataclass
class RSSISample:
    """RSSI measurement from a sensor"""
    sensor_id: str
    bssid: str
    rssi_dbm: float
    timestamp_utc: str
    frequency_mhz: int = 2412


@dataclass
class PositionEstimate:
    """Estimated position of a target"""
    bssid: str
    x: float
    y: float
    z: float = 0.0
    confidence: float = 0.0
    error_radius_m: float = 0.0
    timestamp: str = ""
    method: str = "trilateration"


# =============================================================================
# NTP SYNC
# =============================================================================

class NTPSyncManager:
    """
    Manages time synchronization across sensors.
    Uses NTP offset tracking for consistent timestamps.
    """
    
    def __init__(self):
        self.sensor_offsets: Dict[str, float] = {}  # sensor_id -> offset_ms
        self.reference_time: Optional[datetime] = None
    
    def register_sensor(self, sensor_id: str, ntp_offset_ms: float = 0.0):
        """Register sensor with its NTP offset"""
        self.sensor_offsets[sensor_id] = ntp_offset_ms
        logger.info(f"Registered sensor {sensor_id} with offset {ntp_offset_ms}ms")
    
    def sync_timestamp(self, sensor_id: str, timestamp: datetime) -> datetime:
        """Adjust timestamp based on sensor's NTP offset"""
        offset_ms = self.sensor_offsets.get(sensor_id, 0.0)
        from datetime import timedelta
        return timestamp - timedelta(milliseconds=offset_ms)
    
    def get_sync_status(self) -> Dict:
        """Get synchronization status for all sensors"""
        return {
            'sensors': len(self.sensor_offsets),
            'offsets': dict(self.sensor_offsets),
            'max_drift_ms': max(self.sensor_offsets.values(), default=0) - min(self.sensor_offsets.values(), default=0)
        }


# =============================================================================
# PATH LOSS MODEL
# =============================================================================

class PathLossModel:
    """
    Log-distance path loss model for RSSI → distance estimation.
    
    PL(d) = PL(d0) + 10 * n * log10(d/d0)
    
    Where:
    - PL(d) = path loss at distance d (dB)
    - PL(d0) = path loss at reference distance d0 (typically 1m)
    - n = path loss exponent (environment dependent)
    - d = distance (meters)
    """
    
    # Environment presets
    ENVIRONMENTS = {
        'free_space': {'n': 2.0, 'pl0': -40},
        'indoor_los': {'n': 2.2, 'pl0': -42},      # Line of sight indoor
        'indoor_nlos': {'n': 3.0, 'pl0': -45},     # Non-line of sight
        'indoor_obstructed': {'n': 4.0, 'pl0': -50},
        'outdoor_urban': {'n': 2.7, 'pl0': -41},
        'outdoor_suburban': {'n': 2.4, 'pl0': -40},
    }
    
    def __init__(self, environment: str = 'indoor_los', 
                 reference_rssi: float = None,
                 path_loss_exponent: float = None):
        """
        Initialize path loss model.
        
        Args:
            environment: Preset environment name
            reference_rssi: RSSI at 1 meter (overrides preset)
            path_loss_exponent: Path loss exponent (overrides preset)
        """
        preset = self.ENVIRONMENTS.get(environment, self.ENVIRONMENTS['indoor_los'])
        
        self.pl0 = reference_rssi if reference_rssi is not None else preset['pl0']
        self.n = path_loss_exponent if path_loss_exponent is not None else preset['n']
        self.d0 = 1.0  # Reference distance (meters)
    
    def rssi_to_distance(self, rssi_dbm: float, frequency_mhz: int = 2412) -> float:
        """
        Convert RSSI to estimated distance.
        
        Args:
            rssi_dbm: Received signal strength (dBm)
            frequency_mhz: Frequency (for wavelength adjustment)
            
        Returns:
            Estimated distance in meters
        """
        # Frequency adjustment (optional, for 5GHz vs 2.4GHz)
        freq_factor = 0.0
        if frequency_mhz > 5000:
            freq_factor = -3.0  # 5GHz has higher free-space loss
        
        # Log-distance model inversion
        # RSSI = PL0 - 10 * n * log10(d) + freq_factor
        # log10(d) = (PL0 + freq_factor - RSSI) / (10 * n)
        # d = 10 ^ ((PL0 + freq_factor - RSSI) / (10 * n))
        
        exponent = (self.pl0 + freq_factor - rssi_dbm) / (10 * self.n)
        distance = math.pow(10, exponent)
        
        # Clamp to reasonable range
        return max(0.1, min(distance, 1000.0))
    
    def distance_to_rssi(self, distance_m: float, frequency_mhz: int = 2412) -> float:
        """
        Estimate RSSI at a given distance.
        
        Args:
            distance_m: Distance in meters
            frequency_mhz: Frequency
            
        Returns:
            Estimated RSSI in dBm
        """
        if distance_m <= 0:
            distance_m = 0.1
        
        freq_factor = -3.0 if frequency_mhz > 5000 else 0.0
        rssi = self.pl0 + freq_factor - 10 * self.n * math.log10(distance_m / self.d0)
        
        return rssi


# =============================================================================
# TRILATERATION SOLVER
# =============================================================================

class TrilaterationSolver:
    """
    Solves for target position using multiple distance measurements.
    
    Uses least-squares optimization for overdetermined systems.
    """
    
    def __init__(self, min_sensors: int = 3):
        self.min_sensors = min_sensors
    
    def solve(self, sensors: List[SensorPosition], 
              distances: List[float]) -> Optional[PositionEstimate]:
        """
        Solve for target position.
        
        Args:
            sensors: List of sensor positions
            distances: List of distances from each sensor to target
            
        Returns:
            PositionEstimate or None if insufficient data
        """
        if len(sensors) < self.min_sensors or len(sensors) != len(distances):
            logger.warning(f"Need at least {self.min_sensors} sensors, got {len(sensors)}")
            return None
        
        n = len(sensors)
        
        # For 2D trilateration with 3+ sensors
        # Use linearization: 
        # (x-x1)² + (y-y1)² = d1²
        # (x-x2)² + (y-y2)² = d2²
        # ...
        # Subtract first equation from others to linearize
        
        # Build matrices for least squares: Ax = b
        A = []
        b = []
        
        x1, y1 = sensors[0].x, sensors[0].y
        d1 = distances[0]
        
        for i in range(1, n):
            xi, yi = sensors[i].x, sensors[i].y
            di = distances[i]
            
            # 2*(x1-xi)*x + 2*(y1-yi)*y = d_i² - d_1² - x_i² - y_i² + x_1² + y_1²
            A.append([2 * (x1 - xi), 2 * (y1 - yi)])
            b.append(d1**2 - di**2 - x1**2 - y1**2 + xi**2 + yi**2)
        
        A = np.array(A)
        b = np.array(b)
        
        try:
            # Least squares solution
            result, residuals, rank, s = np.linalg.lstsq(A, b, rcond=None)
            x, y = result[0], result[1]
            
            # Calculate error estimate
            error = 0.0
            for i, sensor in enumerate(sensors):
                estimated_dist = math.sqrt((x - sensor.x)**2 + (y - sensor.y)**2)
                error += (estimated_dist - distances[i])**2
            error = math.sqrt(error / n)
            
            # Confidence based on residual error and sensor count
            confidence = max(0.0, min(1.0, 1.0 - error / 10.0)) * min(1.0, n / 5.0)
            
            return PositionEstimate(
                bssid="",  # Filled by caller
                x=x,
                y=y,
                z=0.0,
                confidence=confidence,
                error_radius_m=error,
                timestamp=datetime.now(timezone.utc).isoformat(),
                method="trilateration"
            )
            
        except np.linalg.LinAlgError as e:
            logger.error(f"Trilateration failed: {e}")
            return None
    
    def solve_from_rssi(self, sensors: List[SensorPosition],
                        samples: List[RSSISample],
                        path_loss: PathLossModel) -> Optional[PositionEstimate]:
        """
        Solve position from RSSI samples.
        
        Args:
            sensors: Known sensor positions
            samples: RSSI samples from sensors
            path_loss: Path loss model for RSSI → distance
            
        Returns:
            PositionEstimate or None
        """
        # Match samples to sensors
        sensor_map = {s.sensor_id: s for s in sensors}
        matched_sensors = []
        distances = []
        
        for sample in samples:
            if sample.sensor_id in sensor_map:
                matched_sensors.append(sensor_map[sample.sensor_id])
                distance = path_loss.rssi_to_distance(sample.rssi_dbm, sample.frequency_mhz)
                distances.append(distance)
        
        if len(matched_sensors) < self.min_sensors:
            return None
        
        estimate = self.solve(matched_sensors, distances)
        if estimate and samples:
            estimate.bssid = samples[0].bssid
        
        return estimate


# =============================================================================
# KALMAN FILTER
# =============================================================================

class KalmanPositionFilter:
    """
    Kalman filter for smoothing position estimates.
    
    Reduces noise and provides velocity estimates.
    """
    
    def __init__(self, process_noise: float = 0.1, measurement_noise: float = 1.0):
        """
        Initialize Kalman filter.
        
        Args:
            process_noise: How much we expect position to change (m²)
            measurement_noise: Measurement uncertainty (m²)
        """
        # State: [x, y, vx, vy]
        self.state = np.array([0.0, 0.0, 0.0, 0.0])
        
        # State covariance
        self.P = np.eye(4) * 10.0
        
        # Process noise covariance
        self.Q = np.eye(4) * process_noise
        
        # Measurement noise covariance (position only)
        self.R = np.eye(2) * measurement_noise
        
        # Measurement matrix (we only measure position)
        self.H = np.array([
            [1, 0, 0, 0],
            [0, 1, 0, 0]
        ])
        
        self.initialized = False
        self.last_update = None
    
    def predict(self, dt: float = 1.0):
        """
        Prediction step.
        
        Args:
            dt: Time step in seconds
        """
        # State transition matrix
        F = np.array([
            [1, 0, dt, 0],
            [0, 1, 0, dt],
            [0, 0, 1, 0],
            [0, 0, 0, 1]
        ])
        
        # Predict state
        self.state = F @ self.state
        
        # Predict covariance
        self.P = F @ self.P @ F.T + self.Q
    
    def update(self, x: float, y: float) -> Tuple[float, float, float]:
        """
        Update step with new measurement.
        
        Args:
            x: Measured x position
            y: Measured y position
            
        Returns:
            Tuple of (filtered_x, filtered_y, uncertainty)
        """
        if not self.initialized:
            self.state = np.array([x, y, 0.0, 0.0])
            self.initialized = True
            self.last_update = datetime.now(timezone.utc)
            return x, y, math.sqrt(self.P[0, 0])
        
        # Time since last update
        now = datetime.now(timezone.utc)
        if self.last_update:
            dt = (now - self.last_update).total_seconds()
            self.predict(dt)
        self.last_update = now
        
        # Measurement
        z = np.array([x, y])
        
        # Innovation
        y_innov = z - self.H @ self.state
        
        # Innovation covariance
        S = self.H @ self.P @ self.H.T + self.R
        
        # Kalman gain
        K = self.P @ self.H.T @ np.linalg.inv(S)
        
        # Update state
        self.state = self.state + K @ y_innov
        
        # Update covariance
        I = np.eye(4)
        self.P = (I - K @ self.H) @ self.P
        
        # Return filtered position and uncertainty
        uncertainty = math.sqrt(self.P[0, 0] + self.P[1, 1])
        return self.state[0], self.state[1], uncertainty
    
    def get_velocity(self) -> Tuple[float, float]:
        """Get current velocity estimate"""
        return self.state[2], self.state[3]


# =============================================================================
# HEATMAP GENERATOR
# =============================================================================

class HeatmapGenerator:
    """
    Generates signal strength heatmaps.
    """
    
    def __init__(self, width_m: float = 50.0, height_m: float = 50.0, 
                 resolution: float = 0.5):
        """
        Initialize heatmap generator.
        
        Args:
            width_m: Map width in meters
            height_m: Map height in meters
            resolution: Grid cell size in meters
        """
        self.width_m = width_m
        self.height_m = height_m
        self.resolution = resolution
        
        self.grid_width = int(width_m / resolution)
        self.grid_height = int(height_m / resolution)
        
        # Signal strength grid (dBm)
        self.grid = np.full((self.grid_height, self.grid_width), -100.0)
        
        # Sample count grid (for averaging)
        self.counts = np.zeros((self.grid_height, self.grid_width))
    
    def add_reading(self, x: float, y: float, rssi_dbm: float):
        """
        Add an RSSI reading to the heatmap.
        
        Args:
            x: X position in meters
            y: Y position in meters
            rssi_dbm: Signal strength
        """
        grid_x = int(x / self.resolution)
        grid_y = int(y / self.resolution)
        
        if 0 <= grid_x < self.grid_width and 0 <= grid_y < self.grid_height:
            # Running average
            count = self.counts[grid_y, grid_x]
            current = self.grid[grid_y, grid_x] if count > 0 else 0
            self.grid[grid_y, grid_x] = (current * count + rssi_dbm) / (count + 1)
            self.counts[grid_y, grid_x] = count + 1
    
    def interpolate(self):
        """Fill gaps using linear interpolation"""
        from scipy import ndimage
        
        # Create mask of measured cells
        mask = self.counts > 0
        
        # Use distance transform for nearest-neighbor interpolation
        if np.any(mask):
            # Get indices of nearest measured cell
            indices = ndimage.distance_transform_edt(~mask, return_indices=True)[1]
            self.grid = self.grid[tuple(indices)]
    
    def export_png(self, filepath: str, 
                   sensors: List[SensorPosition] = None,
                   targets: List[PositionEstimate] = None):
        """
        Export heatmap as PNG.
        
        Args:
            filepath: Output file path
            sensors: Optional sensor positions to overlay
            targets: Optional target positions to overlay
        """
        try:
            import matplotlib.pyplot as plt
            from matplotlib.colors import LinearSegmentedColormap
        except ImportError:
            logger.error("matplotlib required for PNG export")
            return
        
        # Create figure
        fig, ax = plt.subplots(figsize=(10, 10))
        
        # Custom colormap (blue=weak, green=medium, red=strong)
        colors = ['#2E0854', '#1E90FF', '#00FF00', '#FFFF00', '#FF0000']
        cmap = LinearSegmentedColormap.from_list('signal', colors)
        
        # Plot heatmap
        extent = [0, self.width_m, 0, self.height_m]
        im = ax.imshow(self.grid, cmap=cmap, extent=extent, 
                       origin='lower', vmin=-100, vmax=-30)
        
        # Colorbar
        plt.colorbar(im, ax=ax, label='RSSI (dBm)')
        
        # Overlay sensors
        if sensors:
            for s in sensors:
                ax.plot(s.x, s.y, 'w^', markersize=15, markeredgecolor='black')
                ax.annotate(s.sensor_id, (s.x, s.y), color='white', 
                           fontsize=8, ha='center', va='bottom')
        
        # Overlay targets
        if targets:
            for t in targets:
                circle = plt.Circle((t.x, t.y), t.error_radius_m, 
                                   fill=False, color='white', linestyle='--')
                ax.add_patch(circle)
                ax.plot(t.x, t.y, 'wo', markersize=10, markeredgecolor='black')
                ax.annotate(t.bssid[-8:] if t.bssid else 'Target', 
                           (t.x, t.y), color='white', fontsize=8)
        
        # Labels
        ax.set_xlabel('X (meters)')
        ax.set_ylabel('Y (meters)')
        ax.set_title('WiFi Signal Strength Heatmap')
        ax.grid(True, alpha=0.3)
        
        # Save
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Exported heatmap to {filepath}")
    
    def export_svg(self, filepath: str):
        """Export heatmap as SVG"""
        # Use matplotlib with SVG backend
        import matplotlib
        matplotlib.use('SVG')
        self.export_png(filepath.replace('.svg', '.svg'))
    
    def export_json(self, filepath: str) -> str:
        """Export heatmap data as JSON"""
        data = {
            'width_m': self.width_m,
            'height_m': self.height_m,
            'resolution': self.resolution,
            'grid_width': self.grid_width,
            'grid_height': self.grid_height,
            'grid': self.grid.tolist(),
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f)
        
        logger.info(f"Exported heatmap JSON to {filepath}")
        return filepath


# =============================================================================
# GEO-MAPPING ORCHESTRATOR
# =============================================================================

class GeoMapper:
    """
    Orchestrates geo-mapping functionality.
    """
    
    def __init__(self, environment: str = 'indoor_los'):
        self.ntp_sync = NTPSyncManager()
        self.path_loss = PathLossModel(environment=environment)
        self.trilateration = TrilaterationSolver()
        self.filters: Dict[str, KalmanPositionFilter] = {}  # bssid -> filter
        self.sensors: Dict[str, SensorPosition] = {}
        self.heatmap: Optional[HeatmapGenerator] = None
    
    def register_sensor(self, sensor_id: str, x: float, y: float, 
                        z: float = 0.0, ntp_offset_ms: float = 0.0):
        """Register a sensor with known position"""
        self.sensors[sensor_id] = SensorPosition(
            sensor_id=sensor_id, x=x, y=y, z=z, ntp_offset_ms=ntp_offset_ms
        )
        self.ntp_sync.register_sensor(sensor_id, ntp_offset_ms)
    
    def init_heatmap(self, width_m: float = 50.0, height_m: float = 50.0, 
                     resolution: float = 0.5):
        """Initialize heatmap grid"""
        self.heatmap = HeatmapGenerator(width_m, height_m, resolution)
    
    def process_samples(self, samples: List[RSSISample]) -> Optional[PositionEstimate]:
        """
        Process RSSI samples to estimate position.
        
        Args:
            samples: RSSI samples from multiple sensors
            
        Returns:
            Filtered position estimate
        """
        if not samples:
            return None
        
        bssid = samples[0].bssid
        
        # Get trilateration estimate
        sensor_list = [self.sensors[s.sensor_id] for s in samples 
                       if s.sensor_id in self.sensors]
        
        if len(sensor_list) < 3:
            return None
        
        estimate = self.trilateration.solve_from_rssi(sensor_list, samples, self.path_loss)
        
        if not estimate:
            return None
        
        # Apply Kalman filter
        if bssid not in self.filters:
            self.filters[bssid] = KalmanPositionFilter()
        
        filtered_x, filtered_y, uncertainty = self.filters[bssid].update(
            estimate.x, estimate.y
        )
        
        estimate.x = filtered_x
        estimate.y = filtered_y
        estimate.error_radius_m = uncertainty
        estimate.method = "trilateration+kalman"
        
        # Update heatmap
        if self.heatmap:
            for sample in samples:
                if sample.sensor_id in self.sensors:
                    sensor = self.sensors[sample.sensor_id]
                    self.heatmap.add_reading(sensor.x, sensor.y, sample.rssi_dbm)
        
        return estimate


# =============================================================================
# CLI
# =============================================================================

def main():
    """Demo geo-mapping functionality"""
    print("\n" + "="*60)
    print("GEO-MAPPING MODULE DEMO")
    print("="*60)
    
    # Create geo-mapper
    mapper = GeoMapper(environment='indoor_los')
    
    # Register sensors in a triangle formation
    mapper.register_sensor("sensor-1", x=0, y=0)
    mapper.register_sensor("sensor-2", x=20, y=0)
    mapper.register_sensor("sensor-3", x=10, y=17.3)  # Equilateral triangle
    
    print("\n--- Sensor Positions ---")
    for sid, pos in mapper.sensors.items():
        print(f"  {sid}: ({pos.x}, {pos.y})")
    
    # Initialize heatmap
    mapper.init_heatmap(width_m=30, height_m=25, resolution=1.0)
    
    # Simulate samples from a target at (8, 6)
    target_x, target_y = 8, 6
    print(f"\n--- Simulating target at ({target_x}, {target_y}) ---")
    
    # Calculate expected RSSI at each sensor
    for i in range(5):  # 5 measurements
        samples = []
        for sid, sensor in mapper.sensors.items():
            dist = math.sqrt((target_x - sensor.x)**2 + (target_y - sensor.y)**2)
            rssi = mapper.path_loss.distance_to_rssi(dist)
            # Add some noise
            rssi += np.random.normal(0, 2)  # ±2 dB noise
            
            samples.append(RSSISample(
                sensor_id=sid,
                bssid="AA:BB:CC:11:22:33",
                rssi_dbm=rssi,
                timestamp_utc=datetime.now(timezone.utc).isoformat()
            ))
        
        # Process samples
        estimate = mapper.process_samples(samples)
        
        if estimate:
            error = math.sqrt((estimate.x - target_x)**2 + (estimate.y - target_y)**2)
            print(f"  Estimate #{i+1}: ({estimate.x:.2f}, {estimate.y:.2f}) "
                  f"Error: {error:.2f}m, Confidence: {estimate.confidence:.2f}")
    
    print("\n--- Path Loss Model ---")
    pl = mapper.path_loss
    for dist in [1, 5, 10, 20, 50]:
        rssi = pl.distance_to_rssi(dist)
        print(f"  {dist}m → {rssi:.1f} dBm")
    
    print("\n--- NTP Sync Status ---")
    status = mapper.ntp_sync.get_sync_status()
    print(f"  Sensors: {status['sensors']}, Max drift: {status['max_drift_ms']}ms")
    
    print("\nDemo complete!")


if __name__ == '__main__':
    main()
