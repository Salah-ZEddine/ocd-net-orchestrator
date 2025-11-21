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
  
      now = datetime.utcnow()

    # Folder name = date
      day_folder = now.strftime("%Y-%m-%d")
      folder_path = self.output_dir / day_folder
      folder_path.mkdir(parents=True, exist_ok=True)

    # File name = scan prefix + time
      time_part = now.strftime("%H%M%SZ")
      file_path = folder_path / f"{self.prefix}_{time_part}.json"

      with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

      return file_path
