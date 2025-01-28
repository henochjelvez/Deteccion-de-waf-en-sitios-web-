import subprocess
import csv
import re
import socket
from concurrent.futures import ThreadPoolExecutor

def obtener_detalles_dominio(dominio):
    """Obtiene detalles del dominio, incluyendo WAF, IPs, DNS, tecnología, hosting, y tecnología del frontend.

    Args:
      dominio: El dominio a analizar.

    Returns:
      Una tupla con el dominio, WAF, IPs, DNS, tecnología, hosting, tecnología del frontend y si está en Radware.
    """
    try:
        # Ejecuta wafw00f y captura la salida con timeout
        try:
            resultado_waf = subprocess.run(["wafw00f", dominio], capture_output=True, text=True, check=True, timeout=10)
            salida_waf = resultado_waf.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            salida_waf = ""

        # Busca el nombre del WAF
        patron_waf = r"The site .* is behind (.*) WAF"
        coincidencia_waf = re.search(patron_waf, salida_waf)
        waf = coincidencia_waf.group(1) if coincidencia_waf else "No se encontró WAF"

        # Obtiene las IPs asociadas al dominio
        try:
            ips = socket.gethostbyname_ex(dominio)[2]
        except socket.gaierror:
            ips = ["No se pudieron obtener las IPs"]

        # Obtiene la información del DNS
        try:
            resultado_dns = subprocess.run(["nslookup", dominio], capture_output=True, text=True, check=True, timeout=10)
            salida_dns = resultado_dns.stdout
            patron_dns = r"Name:\s*(.*)\nAddress:\s*(.*)"
            coincidencias_dns = re.findall(patron_dns, salida_dns)
            dns = ", ".join([f"{ip} ({nombre})" for nombre, ip in coincidencias_dns])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            dns = "No se pudo obtener la información del DNS"

        # Detecta la tecnología del WAF
        tecnologia_waf = "Desconocida"
        waf_keywords = {
            "cloudflare": "Cloudflare",
            "f5": "F5",
            "imperva": "Imperva",
            "akamai": "Akamai",
            "aws": "AWS WAF",
            "google cloud armor": "Google Cloud Armor",
            "azure": "Azure WAF",
            "radware": "Radware"
        }
        for key, value in waf_keywords.items():
            if key in salida_waf.lower():
                tecnologia_waf = value

        # Detecta la tecnología del frontend
        tecnologia_frontend = "Desconocida"
        frontend_keywords = ["php", "java", "python", "node", "ruby", "go", "asp.net", "react", "angular", "vue"]
        for keyword in frontend_keywords:
            if keyword in salida_waf.lower():
                tecnologia_frontend = keyword.capitalize()

        # Verifica el hosting mediante whois
        try:
            resultado_whois = subprocess.run(["whois", dominio], capture_output=True, text=True, check=True, timeout=10)
            salida_whois = resultado_whois.stdout
            hosting = "Desconocido"
            if "amazon" in salida_whois.lower():
                hosting = "Amazon AWS"
            elif "google" in salida_whois.lower():
                hosting = "Google Cloud"
            elif "microsoft" in salida_whois.lower():
                hosting = "Microsoft Azure"
            elif "ovh" in salida_whois.lower():
                hosting = "OVH"
            elif "digitalocean" in salida_whois.lower():
                hosting = "DigitalOcean"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            hosting = "No se pudo determinar el hosting"

        # Verifica si el dominio está en Radware usando ping
        try:
            resultado_ping = subprocess.run(["ping", "-c", "1", dominio], capture_output=True, text=True, check=True, timeout=5)
            salida_ping = resultado_ping.stdout
            en_radware = "radwarecloud.net" in salida_ping.lower()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            en_radware = False

        return (dominio, waf, ", ".join(ips), dns, tecnologia_waf, hosting, tecnologia_frontend, en_radware)

    except Exception as e:
        print(f"Error al procesar el dominio {dominio}: {e}")
        return None

def generar_reporte_csv(nombre_archivo, datos):
    """Genera un archivo CSV con los datos de los dominios.

    Args:
      nombre_archivo: El nombre del archivo CSV a generar.
      datos: Una lista de tuplas (dominio, waf, ips, dns, tecnologia_waf, hosting, tecnologia_frontend, en_radware).
    """
    with open(nombre_archivo, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Dominio", "WAF", "IPs", "DNS", "Tecnología WAF", "Hosting", "Tecnología Frontend", "En Radware"])
        for row in datos:
            writer.writerow(row)

def procesar_dominio(dominio):
    return obtener_detalles_dominio(dominio)

if __name__ == "__main__":
    archivo_entrada = input("Ingrese el nombre del archivo que contiene los dominios, URLs o IPs a analizar: ").strip()

    try:
        with open(archivo_entrada, 'r') as f:
            dominios = [linea.strip().replace("http://", "").replace("https://", "").replace("www.", "") for linea in f]
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {archivo_entrada}")
        exit(1)

    resultados = []
    with ThreadPoolExecutor() as executor:
        resultados = list(executor.map(procesar_dominio, dominios))

    resultados = [resultado for resultado in resultados if resultado]

    if resultados:
        print("\nResultados del análisis:")
        for resultado in resultados:
            print(resultado)

        guardar_csv = input("\n¿Desea guardar los resultados en un archivo CSV? (s/n): ").strip().lower()
        if guardar_csv == 's':
            nombre_archivo_salida = "reporte_wafs.csv"
            generar_reporte_csv(nombre_archivo_salida, resultados)
            print(f"Reporte generado en {nombre_archivo_salida}")
    else:
        print("No se generaron resultados.")
