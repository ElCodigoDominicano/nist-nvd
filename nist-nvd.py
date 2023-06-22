"""This program (just another python wrapper...) is used to obtain 
vulnerability information from the National Vulnerability Database (NVD) 
provided by the National Institute of Standards and Technology (NIST)
an agency of the U.S. Department of Commerce.

** The Author is not affiliated with any government, government agencies, 
and/or agencies affiliated with the government**

!!! USERS MUST PROVIDE THEIR OWN API KEY GET ONE FROM 
https://nvd.nist.gov/developers/request-an-api-key !!!

NOTE: If you uncomment all lines at the end of this file the program
will write 10 json files in the same directory as the .py file
takes around 2-3 minutes. Only if you choose to write the data grabbed
from the database. This program does not download [ALL] vulnerability 
information from the database. The program still isn't finished just yet.



Author: AERivas
Date: 06/13/2023"""

import requests
import json
import os

from requests.auth import HTTPBasicAuth
from dataclasses import dataclass


@dataclass
class NIST:
    BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    SOURCE_DATA: str = "https://services.nvd.nist.gov/rest/json/source/2.0"
    API_KEY = "YOUR_KEY_PROVIDED_BY_NIST_HERE"
    AUTH = HTTPBasicAuth("apiKey", API_KEY)
    
    def get_source_response(self):
        """retrieve detailed information on the organizations 
        that provide the data contained in the NVD dataset.
        
        ~limit once a day~
        
        Author: AERivas
        Date: 06/21/2023"""
        
        with requests.Session() as s:
            sources_response = s.get(self.SOURCE_DATA, auth=self.AUTH)
        return sources_response
    
    def get_cves_response(self):
        """Common Vulnerabilities and Exposures. The NVD contains 217,963 CVE records. 
        Because of this, its APIs enforce offset-based pagination to answer requests for 
        large collections. Through a series of smaller “chunked” responses controlled by 
        an offset startIndex and a page limit resultsPerPage users may page through all 
        the CVE in the NVD.
        
        !! NOT FULLY IMPLEMENTED YET !!
        
        Parameter base_url: Must be a str datatype as well as  it must be the legit base_url
        Precondition: base_url => https://services.nvd.nist.gov/rest/json/cves/2.0
        Author: AERivas
        Date: 06/14/2023"""
        
        with requests.Session() as s:
            # make the call
            cves_response = s.get(self.BASE_URL, auth=self.AUTH)
        return cves_response
    
    def search_by_identifier(self, identifier: str):
        """Searches the NVD DB via a identifier
    
        Example: https://services.nvd.nist.gov/rest/json/source/2.0?sourceIdentifier=cve@mitre.org
            
        Parameter identifier: Must be a str datatype
        Precondition identifier: is an email found in the glossary labeled "source identifier"
        
        Author: AERivas
        Date: 06/15/2023"""
        
        with requests.Session() as s:
            with_identifier_response = s.get(f"{self.BASE_URL}?sourceIdentifier={identifier}", auth=self.AUTH)
        return with_identifier_response            
        
    def search_by_keyword(self, keyword: str, keyword_exact_match: bool):
        """Searches the NVD DB via a keyword
        
        Request any CVE mentioning "Microsoft"
        https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft 

        Request any CVE mentioning "Windows", "MacOs", and "Debian"
        https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Windows MacOs Debian
            
        Request all CVE mentioning the exact phrase "Microsoft Outlook"
        https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft Outlook&keywordExactMatch 
            
        Parameter keyword: Must be a str datatype
        Parameter keyword_exact_match: Must be a boolean datatype (True/False)
            
        Author: AERivas
        Date: 06/15/2023"""
        
        with requests.Session() as s:
            if keyword_exact_match:
                exact_keyword_response = s.get(f"{self.BASE_URL}keywordSearch={keyword}&keywordExactMatch", auth=self.AUTH)
                return exact_keyword_response
            else:
                not_exact_keyword_response = s.get(f"{self.BASE_URL}?keywordSearch={keyword}", auth=self.AUTH)
                return not_exact_keyword_response

    def search_by_cpe_name(self, cpe_name: str, is_it_vulnerable: bool):
        """Searches the NVD DB via its CPE_NAME if IS_VULNERABLE set to True
        it will return all CVE associated with a specific CPE marked as "vulnerable".
        
        Request the CVE associated a specific CPE
        https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*

        Request the CVE associated a specific CPE using an incomplete name
        https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607 
            
        Request all CVE associated a specific CPE and are marked as vulnerable
        https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607&isVulnerable
           
        Parameter cpe_name: Must be a str datatype 
        Parameter is_it_vulnerable: Must be a boolean (True/False) datatype
            
        Author: AERivas
        Date: 06/17/2023"""
        
        with requests.Session() as s:
            if is_it_vulnerable:
                cpe_is_vulnerable_response = s.get(f"{self.BASE_URL}cpeName={cpe_name}&isVulnerable", auth=self.AUTH)
                return cpe_is_vulnerable_response
            else:
                cpe_isnt_vulnerable_response = s.get(f"{self.BASE_URL}cpeName={cpe_name}", auth=self.AUTH)
                return cpe_isnt_vulnerable_response
                     
    def search_by_cve_identifier(self, year: int, cve_identifier: int):
        """Searches the NVD DB via the year and its Common Vulnerability Exposures (CVE) identifier
            
        Format: {year}-{cve_identifier}
            
        Request a specific CVE using its CVE-ID
        Example: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
            
        Parameter year: Must be a 4-digit integer
        Parameter cve_identifer: Must be a integer, and an approved CVE identifier 
            
        Author: AERivas
        Date: 06/14/2023"""
        
        with requests.Session() as s:
            cve_identifier_response = s.get(f"{self.BASE_URL}?cveId=CVE-{year}-{cve_identifier}", auth=self.AUTH)
        return cve_identifier_response
   
    def cve_with_technical_alerts(self):
        """Request all CVE containing a Technical Alert from US-CERT 
        
        Author: AERivas
        Date: 06/17/2023"""   
        
        with requests.Session() as s:
            cert_alerts_response = s.get(f"{self.BASE_URL}?hasCertAlerts", auth=self.AUTH)
        return cert_alerts_response    
    
    def cve_with_vulnerability_note(self):
        """Request all CVE containing a Vulnerability Note from CERT/CC
        
        Example: https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertNotes
        
        Author: AERivas
        Date: 06/17/2023"""
        
        with requests.Session() as s:
            vulnerability_note_response = s.get(f"{self.BASE_URL}?hasCertNotes", auth=self.AUTH)
        return vulnerability_note_response
                
    def known_exploited_vulnerabilities(self):
        """Request all CVE that appear in the Known Exploited Vulnerabilities (KEV) catalog
        
        Example: https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev 
            
        Author: AERivas
        Date: 06/17/2023"""
        
        with requests.Session() as s:
            kev_catalog_response = s.get(f"{self.BASE_URL}?hasCertNotes", auth=self.AUTH)
        return kev_catalog_response    
                
    def open_vulnerability_assessment_language(self):
        """Request all CVE containing an Open Vulnerability Assessment Language (OVAL) record
        https://services.nvd.nist.gov/rest/json/cves/2.0?hasOval
            
        Author: AERivas
        Date: 06/17/2023"""
        
        with requests.Session() as s:
            oval_response = s.get(f"{self.BASE_URL}?hasOval", auth=self.AUTH)
        return oval_response
     
                      
# Helper Function 1
def get_json_data(response: requests.Response):
    """Response handling function, if everything is ok a JSON 
    (dict in case of python) is RETURNED otherwise an error 
    message is returned
    
    Author: AERivas
    Date: 06/21/2023"""

    # return json data if the status_code was 200, else error message
    if response.status_code == 200: 
        return response.json()
    elif response.status_code == 404:
        return f"{response.status_code} - Page not found."


# Helper Function 2
def does_filename_exist(path):
    """This function checks if the filename the user has
    chosen is taken, if taken it will append a number before
    its file extension
    
    Author: AERivas
    Date: 06/22/2023"""
        
    count = 1
    filename, extension = os.path.splitext(path)
    if extension != ".json":
        exit(f"The file must end with .json as its extension not {extension}. Please try again.")
    while os.path.exists(path):
        path = filename + f"-{count}" + extension
        count += 1    
    return path


# Helper Function 3
def write_to_json_file(data, filename: str) -> None:
    """This function is used to write data grabbed
    from the requests made to the NISTs NVD.
    
    Author: AERivas
    Date: 06/22/2023"""

    json_data = json.dumps(data, indent=4)
    filename = does_filename_exist(filename)
    with open(filename, 'w') as file_object:
        file_object.write(json_data)


if __name__ == '__main__':
    nist = NIST()
    ####### TO TEST UNCOMMENT LINES BELOW #######
    
    # sources = nist.get_source_response()
    # sources_json = get_json_data(sources)
    # write_to_json_file(sources_json, "nist-nvd-sources.json")   

    # cves = nist.get_cves_response()
    # cves_json = get_json_data(cves)
    # write_to_json_file(cves_json, "nist-nvd-cves.json")        
    
    # using_identifier = nist.search_by_identifier('cve@mitre.org')
    # identifier_json = get_json_data(using_identifier)
    # write_to_json_file(identifier_json, 'nist-nvd-identifier.json')      
      
    # using_keyword = nist.search_by_keyword('Microsoft Outlook', False) # Change to True for Exact Keyword Matching
    # keyword_json = get_json_data(using_keyword)
    # write_to_json_file(keyword_json, "nist-nvd-keyword.json")
        
    # cve_id = nist.search_by_cve_identifier(2019, 1010218) #BOTH ARGS MUST BE INTEGERS!! ex: YEAR => 2019 ID => 1010218
    # cve_id_json = get_json_data(cve_id)
    # write_to_json_file(cve_id_json, "nist-nvd-cve-id.json")
        
    # cpe_name = nist.search_by_cpe_name("cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*", False) # Change to True to check if its vulnerable
    # cpe_name_json = get_json_data(cpe_name)    
    # write_to_json_file(cpe_name, "nist-nvd-cpe-name.json")
    
    # technical_alerts = nist.cve_with_technical_alerts()
    # technical_alerts_json = get_json_data(technical_alerts)
    # write_to_json_file(technical_alerts_json, "nist-nvd-technical-alerts.json")
    
    # vulnerability_note = nist.cve_with_vulnerability_note()
    # vulnerability_note_json = get_json_data(vulnerability_note)
    # write_to_json_file(vulnerability_note_json, "nist-nvd-vulnerability-note.json")
    
    # kev_catalog = nist.known_exploited_vulnerabilities()
    # kev_catalog_json = get_json_data(kev_catalog)
    # write_to_json_file(kev_catalog_json, "nist-nvd-kev-catalog.json")
    
    # oval = nist.open_vulnerability_assessment_language()
    # oval_json = get_json_data(oval)
    # write_to_json_file(oval_json, "nist-nvd-oval.json")
    
