from datetime import datetime
import json
from pathlib import Path


class JSONStorage:
    """
    Handles saving data to timestamped JSON files.

    Example:
        storage = JSONStorage(output_dir="data", prefix="discovery")
        path = storage.save({"hosts": [...]})
    """

    def __init__(self, output_dir: Path = Path("data"), prefix: str = "discovery"):
        """
        Initialize the JSON storage.

        Args:
            output_dir: Directory where JSON files will be saved
            prefix: Prefix for the JSON filename
        """
        self.output_dir = output_dir
        self.prefix = prefix
        self.output_dir.mkdir(exist_ok=True)

    def save(self, data: dict) -> Path:
        """
        Save data to a timestamped JSON file.

        Args:
            data: Dictionary to save as JSON

        Returns:
            Path to the saved file
        """
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = self.output_dir / f"{self.prefix}_{timestamp}.json"

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return path