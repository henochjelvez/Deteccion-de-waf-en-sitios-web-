import subprocess
import csv
import re
import socket

def obtener_detalles_dominio(dominio):
    """Obtiene detalles del dominio, incluyendo WAF, IPs, DNS, tecnología y si está en Radware.

    Args:
      dominio: El dominio a analizar.

    Returns:
      Una tupla con el dominio, WAF, IPs, DNS, tecnología y si está en Radware.
    """
    try:
        # Ejecuta wafw00f y captura la salida
        resultado_waf = subprocess.run(["wafw00f", dominio], capture_output=True, text=True, check=True)
        salida_waf = resultado_waf.stdout

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
            resultado_dns = subprocess.run(["nslookup", dominio], capture_output=True, text=True, check=True)
            salida_dns = resultado_dns.stdout
            patron_dns = r"Name:\s*(.*)\nAddress:\s*(.*)"
            coincidencias_dns = re.findall(patron_dns, salida_dns)
            dns = ", ".join([f"{ip} ({nombre})" for nombre, ip in coincidencias_dns])
        except subprocess.CalledProcessError:
            dns = "No se pudo obtener la información del DNS"

        # Detecta la tecnología
        tecnologia = "Desconocida"
        if "nginx" in salida_waf.lower():
            tecnologia = "Nginx"
        elif "apache" in salida_waf.lower():
            tecnologia = "Apache"
        elif "iis" in salida_waf.lower():
            tecnologia = "IIS"
        elif "cpanel" in salida_waf.lower():
            tecnologia = "cPanel"
        elif "oracle" in salida_waf.lower():
            tecnologia = "Oracle"
        elif "cloudflare" in waf.lower():
            tecnologia = "Cloudflare"
        elif any(proveedor in waf.lower() for proveedor in ["radware", "aws", "akamai"]):
            tecnologia = "Balanceador de carga"

        # Verifica si el dominio está en Radware usando ping
        try:
            resultado_ping = subprocess.run(["ping", "-c", "1", dominio], capture_output=True, text=True, check=True)
            salida_ping = resultado_ping.stdout
            en_radware = "radwarecloud.net" in salida_ping.lower()
        except subprocess.CalledProcessError:
            en_radware = False

        return (dominio, waf, ", ".join(ips), dns, tecnologia, en_radware)

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar wafw00f, nslookup o ping para {dominio}: {e}")
        return None
    except Exception as e:
        print(f"Error al procesar la salida para {dominio}: {e}")
        return None

def generar_reporte_csv(nombre_archivo, datos):
    """Genera un archivo CSV con los datos de los dominios.

    Args:
      nombre_archivo: El nombre del archivo CSV a generar.
      datos: Una lista de tuplas (dominio, waf, ips, dns, tecnologia, en_radware).
    """
    with open(nombre_archivo, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Dominio", "WAF", "IPs", "DNS", "Tecnología", "En Radware"])
        for row in datos:
            writer.writerow(row)

if __name__ == "__main__":
    archivo_entrada = input("Ingrese el nombre del archivo que contiene los dominios, URLs o IPs a analizar: ").strip()

    try:
        with open(archivo_entrada, 'r') as f:
            dominios = [linea.strip().replace("http://", "").replace("https://", "").replace("www.", "") for linea in f]
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {archivo_entrada}")
        exit(1)

    resultados = []
    for dominio in dominios:
        resultado = obtener_detalles_dominio(dominio)
        if resultado:
            resultados.append(resultado)

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
