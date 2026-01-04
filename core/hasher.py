import hashlib


class DriverHasher:
    @staticmethod
    def get_sha256(file_path):
        """Вычисляет SHA-256 хеш файла поблочно (для экономии памяти)."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest().lower()
        except (PermissionError, FileNotFoundError):
            return None
