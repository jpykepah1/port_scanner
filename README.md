## 📁 **1. PORT SCANNER AVANZADO** (`port_scanner.py`)

### **Descripción General**
Herramienta profesional de escaneo de puertos que combina múltiples técnicas de escaneo, detección de servicios, fingerprinting de SO y generación de reportes detallados.

### **Instalación**
```bash
# Instalar dependencias principales
pip install scapy

# En Linux, instalar también:
sudo apt-get install tcpdump

# En Windows, instalar WinPcap o Npcap
```

### **Sintaxis Completa**
```bash
python port_scanner.py [OPCIONES] TARGET
```

### **Todos los Parámetros Disponibles**

| Parámetro | Descripción | Valores | Default |
|-----------|-------------|---------|---------|
| `TARGET` | **OBLIGATORIO** - IP o dominio a escanear | Cualquier IP/Dominio | - |
| `-p, --ports` | Puertos a escanear | `common`, `all`, `1-1000`, `22,80,443` | `common` |
| `-t, --scan-type` | Tipo de escaneo | `tcp`, `syn`, `udp` | `tcp` |
| `--threads` | Número máximo de hilos concurrentes | 1-1000 | `100` |
| `--timeout` | Timeout por puerto (segundos) | 0.1-10.0 | `1.0` |
| `--os-detection` | Activar detección de SO | Flag (sin valor) | `False` |
| `--no-host-discovery` | Saltar verificación de host activo | Flag | `False` |
| `--force-scan` | Forzar escaneo aunque host esté inactivo | Flag | `False` |
| `--output-format` | Formato del reporte final | `text`, `json`, `csv` | `text` |
| `-o, --output-file` | Guardar reporte en archivo | Ruta de archivo | - |
| `-v, --verbose` | Modo detallado con más información | Flag | `False` |

### **Ejemplos Prácticos de Uso**

#### **Ejemplo 1: Escaneo Básico para Principiantes**
```bash
# Escaneo simple de puertos comunes en un router local
python port_scanner.py 192.168.1.1

# Salida esperada:
# 🛡️  Advanced Port Scanner - Versión Profesional
# ==================================================
# 🎯 Iniciando escaneo en 192.168.1.1...
# 🟢 Puerto 22/TCP ABIERTO - SSH
# 🟢 Puerto 53/TCP ABIERTO - DNS
# 🟢 Puerto 80/TCP ABIERTO - HTTP
# 🟢 Puerto 443/TCP ABIERTO - HTTPS
# ...
# 📋 REPORTE DE ESCANEO DE PUERTOS - AVANZADO
```

#### **Ejemplo 2: Escaneo Profesional para Auditorías**
```bash
# Escaneo completo con todas las características
sudo python port_scanner.py 192.168.1.100 \
  -p 1-1000 \
  -t syn \
  --os-detection \
  --threads 200 \
  --timeout 0.5 \
  -v \
  -o audit_scan.json \
  --output-format json
```

#### **Ejemplo 3: Escaneo Rápido de Servicios Web**
```bash
# Verificar solo servicios web comunes rápidamente
python port_scanner.py webserver.com \
  -p 80,443,8080,8443,3000,5000 \
  --threads 50 \
  --timeout 1 \
  -v
```

#### **Ejemplo 4: Escaneo UDP para Servicios Específicos**
```bash
# Escanear servicios UDP (más lento, requiere más timeout)
python port_scanner.py dns-server.com \
  -t udp \
  -p 53,67,68,161,162 \
  --timeout 3 \
  -v
```

#### **Ejemplo 5: Escaneo para Monitoreo Continuo**
```bash
# Configuración optimizada para scripts de monitoreo
python port_scanner.py critical-server.local \
  -p 22,80,443,3306,5432,6379 \
  --output-format json \
  -o status_$(date +%Y%m%d_%H%M%S).json \
  --no-host-discovery
```

### **Casos de Uso Específicos**

#### **Para Administradores de Red**
```bash
# Inventario de servicios en toda la red
for ip in 192.168.1.{1..254}; do
  python port_scanner.py $ip -p common -o scan_$ip.json --output-format json
done
```

#### **Para Desarrolladores**
```bash
# Verificar servicios de desarrollo local
python port_scanner.py localhost -p 3000,4200,5000,5432,6379,8080 -v

# Verificar contenedores Docker
python port_scanner.py 172.17.0.2 -p 1-10000 --threads 50
```

#### **Para Auditorías de Seguridad**
```bash
# Escaneo sigiloso con SYN
sudo python port_scanner.py target-company.com \
  -t syn \
  -p 1-10000 \
  --threads 100 \
  --timeout 2 \
  --os-detection \
  -o security_audit.json
```

### **Interpretación de Resultados**

#### **Estados de Puerto en el Reporte**
```text
🟢 ABIERTO    - Servicio activo y accesible
🔴 CERRADO    - No hay servicio escuchando
🟡 FILTRADO   - Firewall está bloqueando las solicitudes
⚪ ERROR      - Error durante el escaneo
```

#### **Niveles de Riesgo**
```text
🔴 ALTO     - Telnet (23), SMB (445), RDP (3389), VNC (5900)
🟡 MEDIO    - FTP (21), HTTP (80), SMTP (25), MySQL (3306)
🟢 BAJO     - SSH (22), HTTPS (443), IMAPS (993), POP3S (995)
```

#### **Ejemplo de Reporte de Seguridad**
```text
⚠️  EVALUACIÓN DE SEGURIDAD:
  Nivel de riesgo: Medium
  Puertos de alto riesgo: 1

🚨 ADVERTENCIAS:
  • Puerto 23 (Telnet): Tráfico no encriptado - Considerar SSH
  • Puerto 80 (HTTP): Considerar migrar a HTTPS

💡 RECOMENDACIONES:
  • Hay 5 puertos abiertos - Revisar necesidad de cada servicio
  • Servicios sin encriptación detectados - Migrar a versiones TLS/SSL
```

---

## 📁 **2. OS FINGERPRINTING INDEPENDIENTE** (`os_fingerprinter.py`)

### **Descripción General**
Módulo especializado exclusivamente en detección avanzada de sistema operativo, usando técnicas sofisticadas de fingerprinting TCP/IP.

### **Sintaxis Completa**
```bash
python os_fingerprinter.py [OPCIONES] TARGET
```

### **Todos los Parámetros Disponibles**

| Parámetro | Descripción | Valores | Default |
|-----------|-------------|---------|---------|
| `TARGET` | **OBLIGATORIO** - IP o dominio a analizar | Cualquier IP/Dominio | - |
| `-p, --ports` | Puertos abiertos conocidos (mejora precisión) | `22,80,443,3389` | - |
| `-q, --quick` | Modo rápido (solo pruebas esenciales) | Flag | `False` |
| `-v, --verbose` | Modo detallado con información técnica | Flag | `False` |
| `-o, --output` | Guardar resultados en archivo JSON | Ruta de archivo | - |

### **Ejemplos Prácticos de Uso**

#### **Ejemplo 1: Fingerprinting Básico**
```bash
# Detección simple del sistema operativo
python os_fingerprinter.py 192.168.1.1

# Salida esperada:
# 🎯 Iniciando fingerprinting en 192.168.1.1...
# 
# ==================================================
# 🖥️  RESULTADOS DE FINGERPRINTING
# ==================================================
# Objetivo: 192.168.1.1
# SO Detectado: Linux
# Familia: Linux  
# Versión: Linux Kernel 5.x
# Confianza: 85%
# Pruebas realizadas: TTL_Analysis, TCP_SYN_Standard, TCP_SYN_With_Options...
```

#### **Ejemplo 2: Fingerprinting Avanzado con Puertos Conocidos**
```bash
# Mayor precisión proporcionando puertos abiertos
python os_fingerprinter.py 192.168.1.100 \
  -p 22,80,443,3389,5985 \
  -v \
  -o os_analysis.json
```

#### **Ejemplo 3: Detección Rápida**
```bash
# Para situaciones donde se necesita velocidad sobre precisión
python os_fingerprinter.py 192.168.1.50 -q
```

#### **Ejemplo 4: Fingerprinting para Auditoría**
```bash
# Análisis completo con toda la información técnica
python os_fingerprinter.py server.company.com \
  -p 22,80,443,993,995,1433,3389 \
  -v \
  -o server_os_audit.json
```

### **Casos de Uso Específicos**

#### **Para Equipos de Seguridad**
```bash
# Identificar sistemas operativos en la red
python os_fingerprinter.py 10.0.1.25 -v -o windows_server_os.json

# Verificar si un servicio está corriendo en el SO esperado
python os_fingerprinter.py web-server.com -p 80,443
```

#### **Para Administradores de Sistemas**
```bash
# Inventario de SO en múltiples servidores
servers=("192.168.1.10" "192.168.1.11" "192.168.1.12")
for server in "${servers[@]}"; do
  echo "Analizando $server..."
  python os_fingerprinter.py $server -q
done
```

#### **Para Desarrolladores**
```bash
# Verificar el SO de servidores de desarrollo
python os_fingerprinter.py staging-server.com -v

# Identificar el SO de un contenedor
python os_fingerprinter.py 172.17.0.3 -p 22,80,3000
```

### **Interpretación de Resultados**

#### **Niveles de Confianza**
```text
95-100%  - Certeza muy alta, múltiples técnicas coinciden
80-94%   - Alta confianza, buena evidencia
60-79%   - Confianza moderada
40-59%   - Baja confianza, posiblemente incorrecto
0-39%    - Muy baja confianza
```

#### **Familias de SO Detectables**
```text
Windows    - 10/11, 8/8.1, 7, Server 2012/2016/2019/2022
Linux      - Kernel 2.6, 3.x, 4.x, 5.x (Ubuntu, CentOS, Debian, etc.)
macOS      - 10.12+, 11.x, 12.x, 13.x, 14.x
BSD        - FreeBSD, OpenBSD, NetBSD
Android    - 5-7, 8-11, 12+
iOS        - 12-14, 15+
```

#### **Ejemplo de Resultado Detallado (Verbose)**
```text
📊 Análisis Detallado:
  TTL: 64 (Consistente: True)
  Pruebas TCP exitosas: 5/6
  Ventana TCP: 65535
  Opciones TCP: MSS, WindowScale, SACK, Timestamp
  Comportamiento ICMP: Respuesta normal

🔧 Técnicas Utilizadas:
  • TTL Analysis
  • TCP Window Size  
  • TCP Options Analysis
  • ICMP Behavior
  • Port Pattern Analysis
```

### **Diferencias Entre Modos**

#### **Modo Completo (Default)**
- **Tiempo**: 20-30 segundos
- **Técnicas**: TTL, TCP Options, ICMP, análisis de puertos
- **Precisión**: 85-95%
- **Uso**: Auditorías, análisis forenses

#### **Modo Rápido (-q)**
- **Tiempo**: 5-10 segundos  
- **Técnicas**: Solo TTL y ventana TCP básica
- **Precisión**: 60-70%
- **Uso**: Escaneos rápidos, monitoreo

---

## 🔄 **Flujos de Trabajo Combinados**

### **Workflow de Auditoría Completa**
```bash
# Paso 1: Escaneo de puertos
python port_scanner.py 192.168.1.100 -p common -v -o ports_scan.json

# Paso 2: Extraer puertos abiertos del JSON
OPEN_PORTS=$(python -c "import json; data=json.load(open('ports_scan.json')); print(','.join(str(p['port']) for p in data['ports']['open']))")

# Paso 3: Fingerprinting avanzado con puertos conocidos
python os_fingerprinter.py 192.168.1.100 -p $OPEN_PORTS -v -o os_analysis.json
```

### **Workflow de Monitoreo Automatizado**
```bash
#!/bin/bash
# monitoring_script.sh

TARGET="192.168.1.100"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "🔍 Iniciando monitoreo de $TARGET..."

# Escaneo rápido de puertos
python port_scanner.py $TARGET -p common --output-format json > port_scan_$TIMESTAMP.json

# Extraer puertos abiertos
OPEN_PORTS=$(python -c "import json, sys; data=json.load(open('port_scan_$TIMESTAMP.json')); ports=','.join(str(p['port']) for p in data['ports']['open']); print(ports)")

# Fingerprinting rápido
python os_fingerprinter.py $TARGET -p $OPEN_PORTS -q > os_scan_$TIMESTAMP.json

echo "✅ Monitoreo completado: port_scan_$TIMESTAMP.json, os_scan_$TIMESTAMP.json"
```

### **Script de Inventario de Red**
```bash
#!/bin/bash
# network_inventory.sh

NETWORK="192.168.1"
OUTPUT_DIR="inventory_$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

echo "🔍 Realizando inventario de red $NETWORK.0/24..."

for i in {1..254}; do
    IP="$NETWORK.$i"
    echo "Analizando $IP..."
    
    # Escaneo rápido
    python port_scanner.py $IP -p common --output-format json > $OUTPUT_DIR/scan_$IP.json 2>/dev/null
    
    # Si hay puertos abiertos, hacer fingerprinting
    if [ -s "$OUTPUT_DIR/scan_$IP.json" ]; then
        python os_fingerprinter.py $IP -q >> $OUTPUT_DIR/os_inventory.json 2>/dev/null
    fi
done

echo "✅ Inventario guardado en directorio: $OUTPUT_DIR"
```

---

## 🛠️ **Solución de Problemas Comunes**

### **Problemas con Port Scanner**

#### **Error: "Scapy requerido para escaneo SYN"**
```bash
# Solución: Instalar scapy
pip install scapy

# O usar escaneo TCP en lugar de SYN
python port_scanner.py 192.168.1.1 -t tcp
```

#### **Error: "Host parece estar inactivo"**
```bash
# Solución: Forzar escaneo o verificar conectividad
python port_scanner.py 192.168.1.1 --force-scan

# O verificar con ping primero
ping 192.168.1.1
```

#### **Escaneo muy lento**
```bash
# Solución: Aumentar hilos y reducir timeout
python port_scanner.py 192.168.1.1 --threads 200 --timeout 0.5
```

### **Problemas con OS Fingerprinting**

#### **Error: "Scapy no disponible"**
```bash
# Solución: Instalar scapy
pip install scapy

# El script funcionará en modo básico sin scapy
```

#### **Baja confianza en los resultados**
```bash
# Solución: Proporcionar puertos abiertos conocidos
python os_fingerprinter.py 192.168.1.1 -p 22,80,443,3389
```

#### **Fingerprinting toma mucho tiempo**
```bash
# Solución: Usar modo rápido
python os_fingerprinter.py 192.168.1.1 -q
```

---

## 📊 **Comparación de Ambos Scripts**

| Característica | Port Scanner | OS Fingerprinting |
|----------------|--------------|-------------------|
| **Propósito principal** | Escanear puertos y servicios | Detectar sistema operativo |
| **Tiempo de ejecución** | 1-30 minutos | 5-30 segundos |
| **Salida** | Lista de puertos, servicios, banners | SO, versión, confianza |
| **Uso típico** | Auditorías de seguridad, inventario | Identificación de sistemas |
| **Requisitos** | Scapy (para SYN), socket | Scapy (para modo completo) |

### **¿Cuándo usar cada uno?**

- **Usa Port Scanner cuando necesites:**
  - Saber qué puertos están abiertos
  - Identificar servicios ejecutándose
  - Realizar auditorías de seguridad completas
  - Generar inventarios de red

- **Usa OS Fingerprinting cuando necesites:**
  - Identificar el SO de un equipo específico
  - Verificar la versión del sistema operativo
  - Análisis forense rápido
  - Complementar información de escaneos

### **Uso Combinado Recomendado**
```bash
# Primero: Escaneo rápido de puertos
python port_scanner.py target.com -p common -o scan.json

# Luego: Fingerprinting con puertos descubiertos
python os_fingerprinter.py target.com -p $(extraer_puertos scan.json) -v
```
