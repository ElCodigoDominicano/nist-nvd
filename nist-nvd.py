"""This program (just another python wrapper...) is used to obtain 
    vulnerabilities from the National Vulnerability Database (NVD) 
    provided by the National Institute of Standards and Technology (NIST)
    an agency of the U.S. Department of Commerce.
    
    ** The Author is not affiliated with any government, government agencies, and/or agencies affiliated with the government**
    
    !!! USERS MUST PROVIDE THEIR OWN API KEY GET ONE FROM https://nvd.nist.gov/developers/request-an-api-key !!!
    
    Author: AERivas
    Date: 06/13/2023
"""
import requests

from requests.auth import HTTPBasicAuth
from dataclasses import dataclass


@dataclass
class NIST:
    API_KEY = "YOUR_KEY_PROVIDED_BY_NIST_HERE"
    AUTH = HTTPBasicAuth("apiKey", API_KEY)
    
            
    def nvd_cve_walker(self, base_url: str):
        """Common Vulnerabilities and Exposures. The NVD contains 217,963 CVE records. 
        Because of this, its APIs enforce offset-based pagination to answer requests for 
        large collections. Through a series of smaller “chunked” responses controlled by 
        an offset startIndex and a page limit resultsPerPage users may page through all 
        the CVE in the NVD.
        
        !! NOT FULLY IMPLEMENTED YET !!
        
        Parameter base_url: Must be a str datatype as well as  it must be the legit base_url
        Precondition: base_url => https://services.nvd.nist.gov/rest/json/cves/2.0
        Author: AERivas
        Date: 06/14/2023
        """
        with requests.Session() as s:
            try:
                # make the call
                res = s.get(base_url, auth=self.AUTH)
                # return json data if the status_code was 200,
                if res.status_code == 200: 
                    return res.json()['sources']
            # else return error message with the given error reason.
            except requests.ConnectionError as ce:
                print(ce.args[0].reason.__str__()[ce.args[0].reason.__str__().find(':')+2:])
                print(f"failed trying to connect to => {ce.request.url}")
                print('Check your internet for connectivity.')
   
    
    def nvd_cve_printer(self, sources):
        """Takes in the JSON Object (dictionary in pythons case)
            prints all data found inside that object.
            
            Parameter sources: is a JSON object (again a dictionary datatype in pythons case.)
            
            Author: AERivas
            Date: 06/15/2023 
        """
        for x in sources:
            v2_extra = ""
            v3_extra = ""
            cwe_extra = ""
            name = x.get('name')
            contact_email = x.get('contactEmail')
            source_ident = x.get('sourceIdentifiers')
            last_mod = x.get('lastModified')
            created = x.get('created')
            v2 = x.get('v2AcceptanceLevel', {})
            v3 = x.get('v3AcceptanceLevel', {})
            cwe = x.get('cweAcceptanceLevel', {})
            try:
                if v2:
                    v2_extra += "Description: " + v2['description']
                    v2_extra += " Last Modified: " + v2['lastModified']
                if v3:
                    v3_extra += "Description: " + v3['description']
                    v3_extra += " Last Modified: " + v3['lastModified']
                if cwe:
                    cwe_extra += "Description: " +cwe['description']
                    cwe_extra += " Last Modified: " + cwe['lastModified']
                if not v2:
                    v2_extra = None
                if not v3:
                    v3_extra = None
                if not cwe:
                    cwe_extra = None
            except KeyError:
                pass # when either v2, v3, and or cwe isn't found
            print(
                "Name:",name,
                "Contact Email", contact_email,
                "Source:", " | ".join(source_ident),
                "Last Modified:", last_mod,
                "Created:", created,
                "V2 =>", v2_extra,
                "V3 =>", v3_extra,
                "CWE =>", cwe_extra)


    def search_by_identifier(self, identifier: str):
        """Searches the NVD DB via a identifier
    
            Example: https://services.nvd.nist.gov/rest/json/source/2.0?sourceIdentifier=cve@mitre.org
            
            Parameter identifier: Must be a str datatype
            Precondition identifier: is an email found in the glossary labeled "source identifier"
            Author: AERivas
            Date: 06/15/2023
        """
        with requests.Session() as s:
            try:
                _identifier = s.get(f" https://services.nvd.nist.gov/rest/json/source/2.0?sourceIdentifier={identifier}", auth=self.AUTH)
                if _identifier.status_code == 200:
                    return _identifier.json()
            except requests.ConnectionError as ce:
                pass
    
            
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
            Date: 06/15/2023
        """
        with requests.Session() as s:
            if keyword_exact_match:
                try:
                    _keyword = s.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&keywordExactMatch", auth=self.AUTH)
                    if _keyword.status_code == 200:
                        return _keyword.json()
                except requests.ConnectionError as ce:
                    pass
            else:
                try:
                    _keyword = s.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}", auth=self.AUTH)
                    if _keyword.status_code == 200:
                        return _keyword.json()
                except requests.ConnectionError as ce:
                    pass
                

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
            Date: 06/17/2023 
        """
        if is_it_vulnerable:
            with requests.Session() as s:
                try:
                    cpe_is_vulnerable = s.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}&isVulnerable", auth=self.AUTH)
                    if cpe_is_vulnerable.status_code == 200:
                        return cpe_is_vulnerable.json()
                except requests.ConnectionError as ce:
                    pass
            
        else:
            with requests.Session() as s:
                try:
                    cpe = s.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}", auth=self.AUTH)
                    if cpe.status_code == 200:
                        return cpe.json()
                except requests.ConnectionError as ce:
                    pass 
                    

    def search_by_cve_identifier(self, year: int, cve_identifier: int):
        """Searches the NVD DB via the year and its Common Vulnerability Exposures (CVE) identifier
            
            Format: {year}-{cve_identifier}
            
            Request a specific CVE using its CVE-ID
            Example: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
            
            Parameter year: Must be a 4-digit integer
            Parameter cve_identifer: Must be a integer, and an approved CVE identifier 
            
            Author: AERivas
            Date: 06/14/2023
        """
        with requests.Session() as s:
            try:
                cve_ident = s.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-{year}-{cve_identifier}", auth=self.AUTH)
                if cve_ident.status_code == 200:
                    return cve_ident.json()
            except requests.ConnectionError as ce:
                pass
    
    
    def cve_with_technical_alerts(self):
        """
            Request all CVE containing a Technical Alert from US-CERT
            https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertAlerts
            
            Author: AERivas
            Date: 06/17/2023
        """   
        with requests.Session() as s:
            try:
                cert_alerts = s.get("https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertAlerts", auth=self.AUTH)
                if cert_alerts.status_code == 200:
                    return cert_alerts.json()
            except requests.ConnectionError as ce:
                pass
                
    
    def cve_with_vulnerability_note(self):
        """
            Request all CVE containing a Vulnerability Note from CERT/CC
            https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertNotes
        
            Author: AERivas
            Date: 06/17/2023
        """
        with requests.Session() as s:
            try:
                vulnerability_note = s.get("https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertNotes", auth=self.AUTH)
                if vulnerability_note.status_code == 200:
                    return vulnerability_note.json()
            except requests.ConnectionError as ce:
                pass
                
                
    def known_exploited_vulnerabilities(self):
        """
            Request all CVE that appear in the Known Exploited Vulnerabilities (KEV) catalog
            https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev 
            
            Author: AERivas
            Date: 06/17/2023        
        """
        with requests.Session() as s:
            try:
                kev_catalog = s.get("https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertNotes", auth=self.AUTH)
                if kev_catalog.status_code == 200:
                    return kev_catalog.json()
            except requests.ConnectionError as ce:
                pass
    
                
    def open_vulnerability_assessment_language(self):
        """
            Request all CVE containing an Open Vulnerability Assessment Language (OVAL) record
            https://services.nvd.nist.gov/rest/json/cves/2.0?hasOval
            
            Author: AERivas
            Date: 06/17/2023
        """
        with requests.Session() as s:
            try:
                oval = s.get("https://services.nvd.nist.gov/rest/json/cves/2.0?hasOval", auth=self.AUTH)
                if oval.status_code == 200:
                    return oval.json()
            except requests.ConnectionError as ce:
                pass


if __name__ == '__main__':
    nist = NIST() # instantiate the NIST Object
    
    ####### TO TEST UNCOMMENT LINES BELOW #######
    
    # base_url = nist.nvd_cve_walker("https://services.nvd.nist.gov/rest/json/cves/2.0")
    # print(base_url)
    
    # data = nist.nvd_cve_printer(base_url)
    # print(data)

    # using_identifier = nist.search_by_identifier('cve@mitre.org')
    # print(using_identifier)
    
    # using_keyword = nist.search_by_keyword('Microsoft Outlook', False) # Change to True for Exact Keyword Matching
    # print(using_keyword)
    
    # cve_id = nist.search_by_cve_identifier(2019, 1010218) #BOTH ARGS MUST BE INTEGERS!! ex: YEAR => 2019 ID => 1010218
    # print(cve_id)
    
    # cpe_name = nist.search_by_cpe_name("cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*", False) # Change to True to check if its vulnerable
    # print(cpe_name)
    
    # technical_alerts = nist.cve_with_technical_alerts()
    # print(technical_alerts)
    
    # vulnerability_note = nist.cve_with_vulnerability_note()
    # print(vulnerability_note)
    
    # kev_catalog = nist.known_exploited_vulnerabilities()
    # print(kev_catalog)
    
    # oval = nist.open_vulnerability_assessment_language()
    # print(oval)
    