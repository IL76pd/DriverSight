import ctypes
import ctypes.wintypes
import os

LPVOID = ctypes.c_void_p
DWORD = ctypes.wintypes.DWORD
LPDWORD = ctypes.POINTER(DWORD)


class DriverCollector:
    def __init__(self):
        try:
            self.psapi = ctypes.WinDLL("psapi.dll")
            self.psapi.EnumDeviceDrivers.argtypes = [
                ctypes.POINTER(LPVOID),
                DWORD,
                LPDWORD,
            ]
            self.psapi.EnumDeviceDrivers.restype = ctypes.wintypes.BOOL
            self.psapi.GetDeviceDriverFileNameA.argtypes = [
                LPVOID,
                ctypes.c_char_p,
                DWORD,
            ]
            self.psapi.GetDeviceDriverFileNameA.restype = DWORD
        except Exception as e:
            pass

    def get_driver_paths(self):
        """WinAPI сбор активных драйверов из памяти."""
        drivers = (LPVOID * 1024)()
        cb_needed = DWORD()
        if not self.psapi.EnumDeviceDrivers(
            drivers, ctypes.sizeof(drivers), ctypes.byref(cb_needed)
        ):
            return []

        count = cb_needed.value // ctypes.sizeof(LPVOID)
        driver_paths = set()

        for i in range(count):
            if not drivers[i]:
                continue
            char_buf = ctypes.create_string_buffer(512)
            if self.psapi.GetDeviceDriverFileNameA(
                drivers[i], char_buf, ctypes.sizeof(char_buf)
            ):
                path = char_buf.value.decode("ascii", errors="ignore")

                if path.lower().startswith("\\systemroot\\"):
                    path = os.path.join(
                        os.environ.get("SystemRoot", "C:\\Windows"), path[12:]
                    )
                elif path.lower().startswith("\\device\\harddiskvolume"):
                    parts = path.split("\\")
                    if len(parts) > 3:
                        path = "C:\\" + "\\".join(parts[3:])
                elif path.startswith("\\??\\"):
                    path = path[4:]

                if os.path.exists(path):
                    driver_paths.add(path)
                else:
                    filename = os.path.basename(path)
                    fallback = os.path.join(
                        os.environ.get("SystemRoot", "C:\\Windows"),
                        "System32",
                        "drivers",
                        filename,
                    )
                    if os.path.exists(fallback):
                        driver_paths.add(fallback)
        return list(driver_paths)

    def get_drivers_from_directory(self, directory_path):
        """Форензик-сбор файлов из указанной папки на диске."""
        driver_paths = set()
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.lower().endswith(".sys"):
                    driver_paths.add(os.path.join(root, file))
        return list(driver_paths)
