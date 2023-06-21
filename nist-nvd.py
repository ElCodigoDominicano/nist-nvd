"""This program (just another python wrapper...) is used to obtain 
vulnerabilities from the National Vulnerability Database (NVD) 
provided by the National Institute of Standards and Technology (NIST)
an agency of the U.S. Department of Commerce.

** The Author is not affiliated with any government, government agencies, and/or agencies affiliated with the government**

!!! USERS MUST PROVIDE THEIR OWN API KEY GET ONE FROM https://nvd.nist.gov/developers/request-an-api-key !!!

Author: AERivas
Date: 06/13/2023"""

import requests

from requests.auth import HTTPBasicAuth
from dataclasses import dataclass


@dataclass
class NIST:
    BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    SOURCE_DATA: str = "https://services.nvd.nist.gov/rest/json/source/2.0"
    API_KEY = "YOUR_KEY_PROVIDED_BY_NIST_HERE"
    AUTH = HTTPBasicAuth("apiKey", API_KEY)
    
    
    def retrieve_sources(self):
        """retrieve detailed information on the organizations 
        that provide the data contained in the NVD dataset.
        
        ~limit once a day~
        
        Author: AERivas
        Date: 06/21/2023
        """
        with requests.Session() as s:
            sources_response = s.get(self.SOURCE_DATA, auth=self.AUTH)
        return sources_response
    
    def nvd_cves(self):
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
def response_checker(response: requests.Response):
    """Response handling function, if everything is ok a JSON 
    (dict in case of python) is RETURNED otherwise an error 
    message is returned
    
    Author: AERivas
    Date: 06/21/2023"""
    
    try:
        # return json data if the status_code was 200, else error
        if response.status_code == 200: 
            return response.json()
        elif response.status_code == 404:
            return f"{response.status_code} - Page not Found."
    except requests.ConnectionError as ce:
        return f"{ce.args[0].reason.__str__()[ce.args[0].reason.__str__().find(':')+2:]} +\
              failed trying to connect to => {ce.request.url} +\
              Please, Check your internet for connectivity."
  
# Helper Function 2
def source_data_printer(sources):
    """Takes in the JSON Object (dictionary in pythons case)
    prints all data found inside that object.
        
    Parameter sources: is a JSON object (again a dictionary datatype in pythons case.)
        
    Author: AERivas
    Date: 06/15/2023"""
    for x in sources.json()['sources']:
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
            "CWE =>", cwe_extra
        )

if __name__ == '__main__': 
    nist = NIST() # instantiate the NIST Object
   
    ####### TO TEST UNCOMMENT LINES BELOW #######
    
    # sources = nist.retrieve_sources()
    # print(source_data_printer(sources))
    
    # cves = nist.nvd_cves()
    # print(response_checker(cves))
        
    # using_identifier = nist.search_by_identifier('cve@mitre.org')
    # print(response_checker(using_identifier))
        
    # using_keyword = nist.search_by_keyword('Microsoft Outlook', False) # Change to True for Exact Keyword Matching
    # print(response_checker(using_keyword))
    
    # cve_id = nist.search_by_cve_identifier(2019, 1010218) #BOTH ARGS MUST BE INTEGERS!! ex: YEAR => 2019 ID => 1010218
    # print(response_checker(cve_id))
    
    # cpe_name = nist.search_by_cpe_name("cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*", False) # Change to True to check if its vulnerable
    # print(response_checker(cpe_name))
    
    # technical_alerts = nist.cve_with_technical_alerts()
    # print(response_checker(technical_alerts))
    
    # vulnerability_note = nist.cve_with_vulnerability_note()
    # print(response_checker(vulnerability_note))    
   
    # kev_catalog = nist.known_exploited_vulnerabilities()
    # print(response_checker(kev_catalog))
    
    # oval = nist.open_vulnerability_assessment_language()
    # print(response_checker(oval))
