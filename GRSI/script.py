from datetime import datetime, timedelta
import requests
import json
import pandas as pd
import os
import time

# Gerando a data atual
now = datetime.now()
formatted_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
three_months_ago = now - timedelta(days=65)  # Aproximadamente 3 meses atrás
formatted_start_date = three_months_ago.strftime("%Y-%m-%dT00:00:00.000Z")
# NVD API URL
excel_file = "gestão de vulnerabilidades.xlsx"
keywords = ["macOS Monterey", "Acrobat", "macOS Big Sur", "Windows Server 2012", "SQL Server 2012", "Microsoft Exchange", "WZR-600DHP", "WZR-HP-G300NH", "Epiphany"]

# Busca de vulnerabilidades
def get_latest_vulnerabilities(keyword):
    print(f"Buscando vulnerabilidade para: {keyword}...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&keywordSearch={keyword}&keywordExactMatch&pubStartDate={formatted_start_date}&pubEndDate={formatted_time}"
    response = requests.get(url, timeout = 30)
    if response.status_code == 200:
        data = response.json()
        new_cves = []
        for cve in data.get("vulnerabilities", []):
            cve_id = cve["cve"]["id"]
            description = cve["cve"]["descriptions"][0]["value"]
            published_date = cve["cve"]["published"]
            dt = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f")
            formatted_date = dt.strftime("%Y-%m-%d")
            cvss = "N/A"
            try: 
                cvss = cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]                
            except KeyError:
                try:
                    cvss = cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                except KeyError:
                    try:
                        cvss = cve["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    except KeyError:
                        pass
            new_cves.append([cve_id, formatted_date, description, cvss, keyword])
            print(f"CVE ID: {cve_id}\nPublished: {published_date}\nDescription: {description}\nCVSS: {cvss}\nPrograma: {keyword}\n")
        return new_cves
    else:
        print("Busca falhou em adquirir dados:", response.status_code)
        return[]
    
def update_excel(all_cves):
    new_data = pd.DataFrame(all_cves, columns=["CVE ID", "Data Publicada", "Descrição", "Nível", "Programa"])
    # Formata a data para o formato YMD
    new_data["Data Publicada"] = pd.to_datetime(new_data["Data Publicada"]).dt.date
    
    if os.path.exists(excel_file):
        # Carrega os dados existentes
        existing_data = pd.read_excel(excel_file)
        
        # Mescla sem duplicar
        final_data = pd.concat([existing_data, new_data]).drop_duplicates(subset=["CVE ID"], keep="first")
        
        # Abre o arquivo existente em modo de adição
        with pd.ExcelWriter(excel_file, mode='a', if_sheet_exists='replace', engine='openpyxl') as writer:
            final_data.to_excel(writer, index=False, sheet_name="CVEs")
    else:
        # Cria um novo arquivo se ele não existe
        new_data.to_excel(excel_file, index=False, sheet_name="CVEs")

    print(f"Updated Excel file: {excel_file}")


if __name__ == "__main__":
    all_cves = []
    for keyword in keywords:
        cves = get_latest_vulnerabilities(keyword)
        all_cves.extend(cves)
        time.sleep(6)

    if all_cves:
        update_excel(all_cves)

    # Se não houver novas vulnerabilidades
    else:
        print("0 CVEs novos encontrados")