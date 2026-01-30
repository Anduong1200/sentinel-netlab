"""
Sentinel NetLab - ML Anomaly Detection Module
Implements a lightweight Autoencoder for unsupervised anomaly detection on network traffic features.

Usage:
1. Export data using `common/export.py`
2. Train model using `train_model()`
3. Deploy model for inference using `detect_anomaly()`
"""

import logging
import os

import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class SimpleAutoencoder(nn.Module):
    """
    Basic Autoencoder for tabular feature data.
    """

    def __init__(self, input_dim):
        super().__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64), nn.ReLU(), nn.Linear(64, 32), nn.ReLU()
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
            nn.Sigmoid(),  # Assumes normalized inputs 0-1
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


def train_model(data_matrix, epochs=50, lr=0.001, save_path="model.pth"):
    """
    Train autoencoder on "normal" baseline data.
    """
    if data_matrix.size == 0:
        logger.error("No data to train on")
        return None

    input_dim = data_matrix.shape[1]
    model = SimpleAutoencoder(input_dim)

    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    # Convert to tensor
    tensor_data = torch.tensor(data_matrix, dtype=torch.float32)

    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        output = model(tensor_data)
        loss = criterion(output, tensor_data)
        loss.backward()
        optimizer.step()

        if epoch % 10 == 0:
            logger.info(f"Epoch {epoch}/{epochs}, Loss: {loss.item():.4f}")

    # Save
    if save_path:
        torch.save(model.state_dict(), save_path)
        logger.info(f"Model saved to {save_path}")

    return model


def load_model(path, input_dim):
    """Load trained model."""
    if not os.path.exists(path):
        return None
    model = SimpleAutoencoder(input_dim)
    model.load_state_dict(torch.load(path, weights_only=True))
    model.eval()
    return model


def detect_anomaly(model, new_vector, threshold=0.05):
    """
    Detect if new vector is anomalous (high reconstruction error).
    Returns (is_anomaly, error_score)
    """
    if model is None:
        return False, 0.0

    with torch.no_grad():
        inputs = torch.tensor(new_vector, dtype=torch.float32)
        reconstruction = model(inputs)
        loss = torch.mean((inputs - reconstruction) ** 2).item()

    return loss > threshold, loss
