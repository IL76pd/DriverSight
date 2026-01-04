import ctypes
import ctypes.wintypes
import os


class DriverCollector:
    def __init__(self):
        self.psapi = ctypes.WinDLL("psapi.dll")
        self.kernel32 = ctypes.WinDLL("kernel32.dll")

    def get_driver_paths(self):
        """Использует WinAPI EnumDeviceDrivers для скрытного получения списка путей."""
        # 1. Получаем список базовых адресов драйверов
        drivers = (ctypes.c_void_p * 1024)()
        cb_needed = ctypes.wintypes.DWORD()

        if not self.psapi.EnumDeviceDrivers(
            ctypes.byref(drivers), ctypes.sizeof(drivers), ctypes.byref(cb_needed)
        ):
            return []

        count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
        driver_paths = set()

        for i in range(count):
            char_buf = ctypes.create_string_buffer(512)
            # 2. Для каждого адреса получаем путь к файлу
            if self.psapi.GetDeviceDriverFileNameA(
                drivers[i], char_buf, ctypes.sizeof(char_buf)
            ):
                path = char_buf.value.decode("ascii", errors="ignore")

                # Исправляем формат пути (Windows возвращает \SystemRoot\ вместо C:\Windows)
                if path.lower().startswith("\\systemroot\\"):
                    path = os.path.join(os.environ["SystemRoot"], path[12:])
                elif path.lower().startswith("\\??\\"):
                    path = path[4:]

                if os.path.exists(path):
                    driver_paths.add(path)

        return list(driver_paths)
