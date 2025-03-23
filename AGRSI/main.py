from datetime import datetime, timedelta
import requests
import pandas as pd
import os
import time

# Gerando a data atual
now = datetime.now()
formatted_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
# Gerando a data de inicio de busca, aproximadamente 2 meses atrás
three_months_ago = now - timedelta(days=75)
formatted_start_date = three_months_ago.strftime("%Y-%m-%dT00:00:00.000Z")

excel_file = "gestão de vulnerabilidades.xlsx"
keywords = ["macOS Monterey", "Acrobat", "macOS Big Sur", "Windows Server 2012", 
            "SQL Server 2012", "Microsoft Exchange", "WZR-600DHP", "WZR-HP-G300NH", "Epiphany"]

# Função para buscar vulnerabilidades
def get_latest_vulnerabilities(keyword):
    print(f"Buscando vulnerabilidades para: {keyword}...")
    # NVD API URL
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&keywordSearch={keyword}&pubStartDate={formatted_start_date}&pubEndDate={formatted_time}" 
    response = requests.get(url, timeout=30)

    if response.status_code == 200:
        data = response.json()
        new_cves = []

        for cve in data.get("vulnerabilities", []):
            cve_id = cve["cve"]["id"]
            description = cve["cve"]["descriptions"][0]["value"]
            published_date = cve["cve"]["published"]
            dt = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f")
            # formatted_date = dt.strftime("%Y-%m-%d")      
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
            
            print(f"CVE ID: {cve_id}\nPublished: {published_date}\nDescription: {description}\nCVSS: {cvss}\nPrograma: {keyword}\n")
            # Armazena o CVE com o termo pesquisado
            new_cves.append([cve_id, dt, description, cvss, keyword])
        
        print(f"Encontrados {len(new_cves)} CVEs para {keyword}\n")
        return new_cves
    else:
        print(f"Erro ao buscar dados para {keyword}: {response.status_code}")
        return []

# Atualiza apenas a aba "CVEs" sem apagar outras planilhas
def update_excel(all_cves):
    new_data = pd.DataFrame(all_cves, columns=["CVE ID", "Data Publicada", "Descrição", "Nível", "Programa"])
    # Formata a data para o formato YMD
    # new_data["Data Publicada"] = pd.to_datetime(new_data["Data Publicada"]).dt.date

    if os.path.exists(excel_file):
        # Carrega os dados existentes
        with pd.ExcelWriter(excel_file, mode="a", engine="openpyxl", if_sheet_exists="overlay") as writer:
            # Carrega os dados da aba "CVEs" se existir
            try:
                existing_data = pd.read_excel(excel_file, sheet_name="CVEs")
                existing_data = existing_data.loc[:, ~existing_data.columns.str.contains('^Unnamed')]

                # Mescla sem duplicar
                combined_data = pd.concat([existing_data, new_data])
                combined_data.drop_duplicates(subset=["CVE ID", "Programa"], keep="first", inplace=True)

            except ValueError:
                # Se a aba "CVEs" não existir, apenas usa os novos dados
                combined_data = new_data

            # Atualiza apenas a aba "CVEs"
            combined_data.to_excel(writer, index=False, sheet_name="CVEs")  

    else:
        # Cria um novo arquivo com a aba "CVEs"
        new_data.to_excel(excel_file, index=False, sheet_name="CVEs")

    print(f"Arquivo Excel atualizado: {excel_file}")

if __name__ == "__main__":
    all_cves = []
    
    for keyword in keywords:
        cves = get_latest_vulnerabilities(keyword)
        all_cves.extend(cves)
        # Evita sobrecarga na API
        time.sleep(6)  

    if all_cves:
        update_excel(all_cves)
    else:
        # Se não houver vulnerabilidades
        print("Nenhum CVE encontrado.")
