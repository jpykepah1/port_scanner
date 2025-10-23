# PORT_SCANNER

## 📁 **Estructura Final del Repositorio**

```
port-scanner-advanced/
│
├── 📄 README.md
├── 📄 requirements.txt
├── 📄 setup.py
├── 📄 LICENSE
├── 📄 .gitignore
├── 📄 CONTRIBUTING.md
├── 📄 CHANGELOG.md
│
├── 📁 src/
│   └── 📁 portscanner/
│       ├── 📄 __init__.py
│       ├── 📄 scanner.py
│       ├── 📄 fingerprint.py
│       ├── 📄 utils.py
│       └── 📄 exceptions.py
│
├── 📁 examples/
│   ├── 📄 basic_scan.py
│   ├── 📄 advanced_scan.py
│   ├── 📄 network_audit.py
│   └── 📄 api_usage.py
│
├── 📁 tests/
│   ├── 📄 __init__.py
│   ├── 📄 test_scanner.py
│   ├── 📄 test_fingerprint.py
│   └── 📄 test_utils.py
│
├── 📁 docs/
│   ├── 📄 installation.md
│   ├── 📄 usage.md
│   ├── 📄 api_reference.md
│   └── 📄 examples.md
│
└── 📁 scripts/
    ├── 📄 install.sh
    ├── 📄 scan_network.sh
    └── 📄 quick_scan.py
```

## 📄 **1. README.md**

```markdown
# 🛡️ Advanced Port Scanner & OS Fingerprinting

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Scapy](https://img.shields.io/badge/built%20with-Scapy-green.svg)](https://scapy.net/)

Una herramienta profesional de escaneo de puertos y detección de sistema operativo escrita en Python.

## ✨ Características

- 🔍 **Escaneo de Puertos Avanzado**: TCP, SYN, UDP
- 🖥️ **Fingerprinting de SO**: Detección avanzada de sistemas operativos
- 📊 **Reportes Detallados**: Texto, JSON, CSV
- 🛡️ **Evaluación de Seguridad**: Análisis automático de riesgos
- ⚡ **Alto Rendimiento**: Gestión optimizada de hilos
- 🔧 **Fácil Integración**: API simple para otros proyectos

## 🚀 Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/jpykepah1/port-scanner-advanced.git
cd port-scanner-advanced

# Instalar dependencias
pip install -r requirements.txt

# Instalar en modo desarrollo
pip install -e .
```

## 📖 Uso Básico

### Como Script

```bash
# Escaneo básico
python -m portscanner.scanner 192.168.1.1

# Escaneo avanzado con OS detection
python -m portscanner.scanner example.com -p 1-1000 -t syn --os-detection -v

# Solo fingerprinting de SO
python -m portscanner.fingerprint 192.168.1.1 -p 22,80,443
```

### Como Módulo Python

```python
from portscanner import PortScanner, OSFingerprinter

# Escaneo de puertos
scanner = PortScanner(target="192.168.1.1")
results = scanner.scan()

# Fingerprinting de SO
fingerprinter = OSFingerprinter()
os_info = fingerprinter.detect("192.168.1.1")
```

## 🎯 Ejemplos

### Escaneo Completo de Red

```python
from portscanner import NetworkAudit

audit = NetworkAudit()
report = audit.scan_network("192.168.1.0/24")
audit.generate_report("network_audit.html")
```

### Monitoreo Continuo

```python
from portscanner import ServiceMonitor

monitor = ServiceMonitor(targets=["web.server.com", "db.server.com"])
monitor.start_monitoring(interval=300)  # Cada 5 minutos
```

## 📋 Características Detalladas

### Tipos de Escaneo
- **TCP Connect**: Escaneo por conexión completa
- **SYN Stealth**: Escaneo sigiloso (medio abierto)
- **UDP Scan**: Escaneo de servicios UDP
- **OS Detection**: Fingerprinting avanzado de SO

### Formatos de Salida
- **Texto**: Reporte legible en terminal
- **JSON**: Para procesamiento automático
- **CSV**: Para hojas de cálculo
- **HTML**: Reportes visuales

## 🛠️ Requisitos

- Python 3.8 o superior
- Scapy 2.4.5 o superior
- Permisos de administrador para escaneo SYN

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Por favor lee [CONTRIBUTING.md](CONTRIBUTING.md) para detalles.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver [LICENSE](LICENSE) para detalles.

## ⚠️ Aviso Legal

Esta herramienta está diseñada para:
- Auditorías de seguridad autorizadas
- Pruebas de penetración éticas
- Administración de sistemas
- Investigación de seguridad

**Úsala solo en sistemas que te pertenezcan o tengas permiso explícito para probar.**
```

## 📄 **2. requirements.txt**

```txt
scapy>=2.4.5
ipaddress>=1.0.23
typing-extensions>=4.0.0; python_version < "3.8"
```

## 📄 **3. setup.py**

```python
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="portscanner-advanced",
    version="1.0.0",
    author="jpykepah1",
    author_email="tu-email@example.com",
    description="Advanced Port Scanner and OS Fingerprinting Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jpykepah1/port-scanner-advanced",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "portscanner=portscanner.scanner:main",
            "osfingerprint=portscanner.fingerprint:main",
        ],
    },
    keywords="portscanner, security, networking, os fingerprinting",
    project_urls={
        "Bug Reports": "https://github.com/jpykepah1/port-scanner-advanced/issues",
        "Source": "https://github.com/jpykepah1/port-scanner-advanced",
    },
)
```

## 📄 **4. LICENSE**

```text
MIT License

Copyright (c) 2024 jpykepah1

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 📄 **5. .gitignore**

```gitignore
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Testing
.coverage
.pytest_cache/
htmlcov/

# Documentation
docs/_build/

# Scan results
*.json
*.csv
*.html
scan_results/
reports/

# Environment variables
.env
.secrets
```

## 📄 **6. CONTRIBUTING.md**

```markdown
# Guía de Contribución

¡Gracias por tu interés en contribuir a Port Scanner Advanced!

## 🎯 Cómo Contribuir

### Reportar Errores
1. Usa el sistema de issues de GitHub
2. Incluye información detallada:
   - Versión de Python
   - Sistema operativo
   - Comando ejecutado
   - Error completo
   - Logs relevantes

### Sugerir Mejoras
1. Abre un issue con la etiqueta "enhancement"
2. Describe la funcionalidad propuesta
3. Explica el caso de uso

### Enviar Pull Requests
1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 🛠️ Configuración del Entorno de Desarrollo

```bash
# Clonar y configurar
git clone https://github.com/jpykepah1/port-scanner-advanced.git
cd port-scanner-advanced
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Instalar en modo desarrollo
pip install -e .[dev]

# Ejecutar tests
pytest tests/
```

## 📝 Estándares de Código

- Sigue PEP 8
- Usa type hints
- Escribe docstrings
- Incluye tests para nuevas funcionalidades
- Actualiza la documentación

## 🧪 Testing

```bash
# Ejecutar todos los tests
pytest

# Con cobertura
pytest --cov=portscanner

# Tests específicos
pytest tests/test_scanner.py
```

## 📚 Documentación

- Actualiza README.md para cambios significativos
- Documenta nuevas funciones con docstrings
- Actualiza examples/ si es necesario

## 🐛 Encontraste un Bug?

1. Revisa los issues existentes
2. Crea un nuevo issue con el template de bug
3. Incluye pasos para reproducir
4. Agrega logs y screenshots si es posible

## 💡 Ideas para Contribuir

- Mejoras en el fingerprinting de SO
- Nuevos tipos de escaneo
- Mejoras en rendimiento
- Exportación a más formatos
- Integración con otras herramientas
- Mejoras en la documentación
```

## 📁 **7. Estructura del Código Refactorizado**

### **src/portscanner/__init__.py**

```python
"""
Port Scanner Advanced - Herramienta profesional de escaneo de red
"""

__version__ = "1.0.0"
__author__ = "jpykepah1"
__description__ = "Advanced Port Scanner and OS Fingerprinting Tool"

from .scanner import PortScanner, NetworkAudit, ServiceMonitor
from .fingerprint import OSFingerprinter, StandaloneFingerprinter
from .utils import NetworkUtils, ServiceDetector
from .exceptions import PortScannerError, NetworkError, FingerprintError

__all__ = [
    "PortScanner",
    "NetworkAudit", 
    "ServiceMonitor",
    "OSFingerprinter",
    "StandaloneFingerprinter",
    "NetworkUtils",
    "ServiceDetector",
    "PortScannerError",
    "NetworkError",
    "FingerprintError",
]
```

### **src/portscanner/exceptions.py**

```python
"""
Excepciones personalizadas para Port Scanner Advanced
"""

class PortScannerError(Exception):
    """Excepción base para errores del escáner"""
    pass

class NetworkError(PortScannerError):
    """Error de red o conectividad"""
    pass

class FingerprintError(PortScannerError):
    """Error en fingerprinting de SO"""
    pass

class ConfigurationError(PortScannerError):
    """Error en configuración"""
    pass

class ScanError(PortScannerError):
    """Error durante el escaneo"""
    pass

class PermissionError(PortScannerError):
    """Error de permisos"""
    pass
```

### **src/portscanner/utils.py**

```python
"""
Utilidades y clases base para Port Scanner Advanced
"""

import socket
import ipaddress
import platform
import subprocess
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from .exceptions import NetworkError

class NetworkUtils:
    """Utilidades de red y validaciones"""
    
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, Optional[str], str]:
        """Valida y resuelve objetivo"""
        try:
            ipaddress.ip_address(target)
            return True, target, "OK"
        except ValueError:
            try:
                resolved_ip = socket.gethostbyname(target)
                return True, resolved_ip, f"Dominio resuelto: {target} -> {resolved_ip}"
            except socket.gaierror as e:
                return False, None, f"Error resolviendo dominio: {e}"
    
    @staticmethod
    def get_local_network_info() -> Dict[str, Any]:
        """Obtiene información de red local"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            interface_ip = s.getsockname()[0]
            s.close()
            
            return {
                "hostname": hostname,
                "local_ip": local_ip,
                "interface_ip": interface_ip,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise NetworkError(f"No se pudo obtener información de red: {e}")

class ServiceDetector:
    """Detector de servicios y banners"""
    
    def __init__(self):
        self.service_db = self._load_service_database()
    
    def _load_service_database(self) -> Dict[int, Dict[str, Any]]:
        """Carga base de datos de servicios"""
        return {
            21: {"name": "FTP", "protocol": "TCP", "risk": "Medium"},
            22: {"name": "SSH", "protocol": "TCP", "risk": "Low"},
            # ... (base de datos completa)
        }
    
    def detect_service(self, target: str, port: int, protocol: str = "TCP") -> Dict[str, Any]:
        """Detecta servicio en puerto"""
        service_info = self.service_db.get(port, {
            "name": "Unknown", 
            "protocol": protocol, 
            "risk": "Unknown"
        })
        
        # Intenta obtener banner
        banner = self._grab_banner(target, port, protocol)
        if banner:
            service_info["banner"] = banner
            
        return service_info
    
    def _grab_banner(self, target: str, port: int, protocol: str) -> Optional[str]:
        """Intenta obtener banner del servicio"""
        try:
            sock = socket.socket(
                socket.AF_INET, 
                socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
            )
            sock.settimeout(3)
            
            if protocol == "TCP":
                sock.connect((target, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                sock.sendto(b"\r\n", (target, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            return banner if banner else None
            
        except Exception:
            return None
```

### **src/portscanner/scanner.py** (Versión Modular)

```python
#!/usr/bin/env python3
"""
Port Scanner Advanced - Módulo principal de escaneo
"""

import argparse
import sys
from typing import Dict, Any, List
from datetime import datetime

from .utils import NetworkUtils, ServiceDetector
from .fingerprint import OSFingerprinter
from .exceptions import PortScannerError, NetworkError

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PortScanner:
    """Escáner de puertos avanzado"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.target = config['target']
        
        self.network_utils = NetworkUtils()
        self.service_detector = ServiceDetector()
        self.os_fingerprinter = OSFingerprinter()
        
        self.results = self._initialize_results()
        self.stats = self._initialize_stats()
    
    def _initialize_results(self) -> Dict[str, Any]:
        """Inicializa estructura de resultados"""
        return {
            'scan_info': {
                'target': self.target,
                'start_time': None,
                'end_time': None,
                'duration': None,
                'scan_type': self.config.get('scan_type', 'tcp'),
                'ports_scanned': 0
            },
            'host_info': {},
            'os_detection': {},
            'ports': {'open': [], 'closed': [], 'filtered': []},
            'security_assessment': {},
            'errors': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """Ejecuta escaneo completo"""
        try:
            # Validación inicial
            if not self._validate_environment():
                raise PortScannerError("Validación del entorno fallida")
            
            # Descubrimiento de host
            if not self._host_discovery():
                if not self.config.get('force_scan', False):
                    raise NetworkError("Host inaccesible")
            
            # Escaneo de puertos
            self._scan_ports()
            
            # Detección de SO
            if self.config.get('os_detection', True):
                self._perform_os_detection()
            
            # Análisis de seguridad
            self._perform_security_assessment()
            
            return self.results
            
        except Exception as e:
            self._log_error(f"Error durante el escaneo: {e}")
            raise
    
    def generate_report(self, format: str = 'text') -> str:
        """Genera reporte en formato especificado"""
        if format == 'json':
            return self._generate_json_report()
        elif format == 'csv':
            return self._generate_csv_report()
        else:
            return self._generate_text_report()
    
    # ... (métodos de implementación similares al código original)

def main():
    """Función principal para uso como script"""
    parser = argparse.ArgumentParser(
        description='🛡️ Advanced Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='IP o dominio objetivo')
    parser.add_argument('-p', '--ports', default='common', help='Puertos a escanear')
    parser.add_argument('-t', '--scan-type', choices=['tcp', 'syn', 'udp'], default='tcp')
    parser.add_argument('--threads', type=int, default=100)
    parser.add_argument('--timeout', type=float, default=1.0)
    parser.add_argument('--os-detection', action='store_true')
    parser.add_argument('--output-format', choices=['text', 'json', 'csv'], default='text')
    parser.add_argument('-o', '--output-file')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    config = {
        'target': args.target,
        'ports': args.ports,
        'scan_type': args.scan_type,
        'threads': args.threads,
        'timeout': args.timeout,
        'os_detection': args.os_detection,
        'verbose': args.verbose
    }
    
    try:
        scanner = PortScanner(config)
        results = scanner.scan()
        report = scanner.generate_report(args.output_format)
        
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            print(f"Reporte guardado en: {args.output_file}")
        else:
            print(report)
            
    except PortScannerError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nEscaneo interrumpido por el usuario")
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### **src/portscanner/fingerprint.py**

```python
#!/usr/bin/env python3
"""
OS Fingerprinting Advanced - Módulo de detección de SO
"""

import argparse
import json
from typing import Dict, Any, List, Optional

from .utils import NetworkUtils
from .exceptions import FingerprintError

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class OSFingerprinter:
    """Sistema avanzado de fingerprinting de SO"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.signature_database = self._load_signatures()
    
    def detect(self, target: str, open_ports: List[int] = None) -> Dict[str, Any]:
        """Ejecuta detección de SO"""
        if not SCAPY_AVAILABLE:
            raise FingerprintError("Scapy requerido para fingerprinting")
        
        results = {
            "target": target,
            "detected_os": "Unknown",
            "confidence": 0,
            "methods_used": [],
            "detailed_analysis": {}
        }
        
        try:
            # Análisis de TTL
            ttl_results = self._analyze_ttl(target)
            results["detailed_analysis"]["ttl"] = ttl_results
            results["methods_used"].append("TTL")
            
            # Fingerprinting TCP
            tcp_results = self._perform_tcp_tests(target, open_ports)
            results["detailed_analysis"]["tcp"] = tcp_results
            results["methods_used"].extend(list(tcp_results.keys()))
            
            # Determinar SO
            final_detection = self._correlate_results(ttl_results, tcp_results, open_ports)
            results.update(final_detection)
            
            return results
            
        except Exception as e:
            raise FingerprintError(f"Error en fingerprinting: {e}")
    
    # ... (métodos de implementación del fingerprinting)

class StandaloneFingerprinter:
    """Fingerprinter para uso independiente"""
    
    def __init__(self, verbose: bool = False):
        self.fingerprinter = OSFingerprinter(verbose)
    
    def quick_detect(self, target: str) -> str:
        """Detección rápida de SO"""
        try:
            results = self.fingerprinter.detect(target)
            return results.get('detected_os', 'Unknown')
        except FingerprintError:
            return "Unknown"
    
    def comprehensive_detect(self, target: str, open_ports: List[int] = None) -> Dict[str, Any]:
        """Detección comprehensiva"""
        return self.fingerprinter.detect(target, open_ports)

def main():
    """Función principal para uso como script"""
    parser = argparse.ArgumentParser(description='🖥️ Advanced OS Fingerprinting')
    parser.add_argument('target', help='IP objetivo')
    parser.add_argument('-p', '--ports', help='Puertos abiertos conocidos')
    parser.add_argument('-q', '--quick', action='store_true', help='Modo rápido')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-o', '--output', help='Archivo de salida JSON')
    
    args = parser.parse_args()
    
    open_ports = None
    if args.ports:
        open_ports = [int(p.strip()) for p in args.ports.split(',')]
    
    try:
        fingerprinter = StandaloneFingerprinter(verbose=args.verbose)
        
        if args.quick:
            os_name = fingerprinter.quick_detect(args.target)
            print(f"SO detectado: {os_name}")
        else:
            results = fingerprinter.comprehensive_detect(args.target, open_ports)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Resultados guardados en: {args.output}")
            else:
                print(json.dumps(results, indent=2))
                
    except FingerprintError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

## 📁 **8. Ejemplos de Uso**

### **examples/basic_scan.py**

```python
#!/usr/bin/env python3
"""
Ejemplo básico de uso del Port Scanner Advanced
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from portscanner import PortScanner, OSFingerprinter

def main():
    """Ejemplo de escaneo básico"""
    target = "192.168.1.1"
    
    print(f"🎯 Escaneando {target}...")
    
    # Configuración del escáner
    config = {
        'target': target,
        'ports': 'common',
        'scan_type': 'tcp',
        'threads': 50,
        'timeout': 2,
        'os_detection': True,
        'verbose': True
    }
    
    # Ejecutar escaneo
    scanner = PortScanner(config)
    results = scanner.scan()
    
    # Mostrar resultados
    print("\n" + "="*50)
    print("📊 RESULTADOS DEL ESCANEO")
    print("="*50)
    
    open_ports = results['ports']['open']
    print(f"Puertos abiertos encontrados: {len(open_ports)}")
    
    for port_info in open_ports:
        service = port_info.get('service', {})
        print(f"  🚪 Puerto {port_info['port']}/{port_info['protocol']}")
        print(f"     Servicio: {service.get('name', 'Unknown')}")
        print(f"     Riesgo: {service.get('risk', 'Unknown')}")
    
    # Información del SO
    os_info = results.get('os_detection', {})
    if os_info.get('detected_os') != 'Unknown':
        print(f"\n🖥️  Sistema Operativo: {os_info['detected_os']}")
        print(f"   Confianza: {os_info.get('confidence', 0)}%")

if __name__ == '__main__':
    main()
```

### **examples/network_audit.py**

```python
#!/usr/bin/env python3
"""
Ejemplo de auditoría de red completa
"""

import json
from datetime import datetime
from portscanner import PortScanner, OSFingerprinter

class NetworkAudit:
    """Auditoría completa de red"""
    
    def __init__(self):
        self.results = {}
    
    def scan_network(self, network_range: str):
        """Escanea un rango de red completo"""
        print(f"🔍 Iniciando auditoría de red: {network_range}")
        
        # En un escenario real, aquí se expandiría el rango de red
        targets = ["192.168.1.1", "192.168.1.100", "192.168.1.150"]
        
        for target in targets:
            print(f"\n🎯 Analizando {target}...")
            
            try:
                # Escaneo de puertos
                scanner_config = {
                    'target': target,
                    'ports': 'common',
                    'scan_type': 'tcp',
                    'threads': 30,
                    'timeout': 3,
                    'os_detection': True,
                    'verbose': False
                }
                
                scanner = PortScanner(scanner_config)
                port_results = scanner.scan()
                
                # Almacenar resultados
                self.results[target] = {
                    'ports': port_results,
                    'timestamp': datetime.now().isoformat()
                }
                
                print(f"   ✅ Completado - {len(port_results['ports']['open'])} puertos abiertos")
                
            except Exception as e:
                print(f"   ❌ Error: {e}")
                self.results[target] = {'error': str(e)}
    
    def generate_report(self, filename: str):
        """Genera reporte de auditoría"""
        report = {
            'audit_info': {
                'timestamp': datetime.now().isoformat(),
                'targets_scanned': len(self.results),
                'summary': self._generate_summary()
            },
            'detailed_results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Reporte guardado en: {filename}")
    
    def _generate_summary(self):
        """Genera resumen de la auditoría"""
        total_open_ports = 0
        detected_os = []
        
        for target, results in self.results.items():
            if 'ports' in results:
                open_ports = results['ports']['ports']['open']
                total_open_ports += len(open_ports)
                
                os_info = results['ports'].get('os_detection', {})
                if os_info.get('detected_os') != 'Unknown':
                    detected_os.append(f"{target}: {os_info['detected_os']}")
        
        return {
            'total_open_ports': total_open_ports,
            'detected_operating_systems': detected_os,
            'targets_count': len(self.results)
        }

def main():
    """Ejemplo de auditoría de red"""
    audit = NetworkAudit()
    audit.scan_network("192.168.1.0/24")
    audit.generate_report("network_audit.json")

if __name__ == '__main__':
    main()
```

## 📁 **9. Tests Básicos**

### **tests/test_scanner.py**

```python
#!/usr/bin/env python3
"""
Tests para el módulo de escaneo
"""

import unittest
from unittest.mock import patch, MagicMock
from portscanner import PortScanner
from portscanner.exceptions import PortScannerError

class TestPortScanner(unittest.TestCase):
    
    def setUp(self):
        """Configuración inicial para cada test"""
        self.config = {
            'target': '127.0.0.1',
            'ports': 'common',
            'scan_type': 'tcp',
            'threads': 10,
            'timeout': 1,
            'verbose': False
        }
    
    def test_scanner_initialization(self):
        """Test de inicialización del escáner"""
        scanner = PortScanner(self.config)
        self.assertEqual(scanner.target, '127.0.0.1')
        self.assertEqual(scanner.config['scan_type'], 'tcp')
    
    @patch('portscanner.scanner.SCAPY_AVAILABLE', False)
    def test_syn_scan_without_scapy(self):
        """Test de escaneo SYN sin Scapy disponible"""
        self.config['scan_type'] = 'syn'
        
        with self.assertRaises(PortScannerError):
            scanner = PortScanner(self.config)
            scanner.scan()
    
    def test_invalid_target(self):
        """Test con objetivo inválido"""
        self.config['target'] = 'invalid-target.xyz'
        
        scanner = PortScanner(self.config)
        with self.assertRaises(PortScannerError):
            scanner.scan()

if __name__ == '__main__':
    unittest.main()
```

## 📁 **10. Scripts de Utilidad**

### **scripts/install.sh**

```bash
#!/bin/bash
#
# Script de instalación para Port Scanner Advanced
#

echo "🛡️  Instalando Port Scanner Advanced..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 no está instalado"
    exit 1
fi

# Crear entorno virtual
echo "📦 Creando entorno virtual..."
python3 -m venv venv

# Activar entorno virtual
echo "🔧 Activando entorno virtual..."
source venv/bin/activate

# Instalar dependencias
echo "📚 Instalando dependencias..."
pip install -r requirements.txt

# Instalar en modo desarrollo
echo "🚀 Instalando Port Scanner Advanced..."
pip install -e .

echo "✅ Instalación completada!"
echo ""
echo "📖 Para usar el escáner:"
echo "   source venv/bin/activate"
echo "   portscanner --help"
echo ""
echo "🖥️  Para fingerprinting de SO:"
echo "   osfingerprint --help"
```

### **scripts/quick_scan.py**

```python
#!/usr/bin/env python3
"""
Script rápido para escaneos comunes
"""

import sys
import argparse
from portscanner import PortScanner

def quick_scan(target, scan_type='tcp', output_file=None):
    """Ejecuta escaneo rápido"""
    config = {
        'target': target,
        'ports': 'common',
        'scan_type': scan_type,
        'threads': 100,
        'timeout': 1,
        'os_detection': True,
        'verbose': True
    }
    
    scanner = PortScanner(config)
    results = scanner.scan()
    
    if output_file:
        report = scanner.generate_report('json')
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"Reporte guardado en: {output_file}")
    else:
        report = scanner.generate_report('text')
        print(report)

def main():
    parser = argparse.ArgumentParser(description='Escaneo rápido de puertos')
    parser.add_argument('target', help='Objetivo a escanear')
    parser.add_argument('-t', '--type', choices=['tcp', 'syn'], default='tcp')
    parser.add_argument('-o', '--output', help='Archivo de salida')
    
    args = parser.parse_args()
    
    try:
        quick_scan(args.target, args.type, args.output)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

## 📁 **11. Documentación**

### **docs/installation.md**

```markdown
# Guía de Instalación

## Requisitos del Sistema

- Python 3.8 o superior
- pip (gestor de paquetes de Python)
- Permisos de administrador para escaneo SYN

## Instalación desde GitHub

```bash
# Clonar el repositorio
git clone https://github.com/jpykepah1/port-scanner-advanced.git
cd port-scanner-advanced

# Ejecutar script de instalación
chmod +x scripts/install.sh
./scripts/install.sh
```

## Instalación Manual

```bash
# Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Instalar dependencias
pip install scapy

# Instalar el paquete
pip install -e .
```

## Verificación de la Instalación

```bash
# Verificar que los comandos estén disponibles
portscanner --help
osfingerprint --help

# Probar escaneo básico
portscanner 127.0.0.1 -p 22,80,443
```

## Solución de Problemas

### Error: "Scapy no disponible"
```bash
pip install --upgrade scapy
```

### Error de permisos (escaneo SYN)
```bash
# En Linux/Mac
sudo portscanner target.com -t syn

# En Windows, ejecutar como administrador
```

### Firewall bloqueando escaneos
- Verificar configuración del firewall
- Ajustar timeouts: `--timeout 3`
- Reducir hilos: `--threads 20`
```

## 🚀 **Comandos para Subir a GitHub**

```bash
# Inicializar repositorio
git init
git add .
git commit -m "feat: Initial commit - Advanced Port Scanner & OS Fingerprinting"

# Conectar con GitHub (crea el repo primero en GitHub)
git remote add origin https://github.com/jpykepah1/port-scanner-advanced.git
git branch -M main
git push -u origin main

# Para releases
git tag v1.0.0
git push origin v1.0.0
```

## 📦 **Para Publicar en PyPI (Opcional)**

```bash
# Instalar herramientas de empaquetado
pip install build twine

# Construir distribución
python -m build

# Subir a PyPI
twine upload dist/*
```
