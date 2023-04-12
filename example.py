"""
Это пример использования сканера портов в python скрипте
"""

import subprocess
import json

def scan(addr: str, port: int) -> map:
    cmd = ["portScanner", "--addr", addr, "--ports", f"{port}", "--json", "--timeout", "2"]
    return json.loads(subprocess.check_output(cmd))

if __name__ == "__main__":
    data = scan("google.com", 443)
    print(data["443"]) #далее можно использовть данные о портах в своих целях