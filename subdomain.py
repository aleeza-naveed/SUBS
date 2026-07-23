#!/usr/bin/env python3
"""
Subdomain discovery via ViewDNS.info API.
"""
import requests
import json
from config import VIEWDNS_API_KEY

def find_subdomains(domain):
    """
    Fetches subdomains from ViewDNS.info API.
    Returns an empty list if the API fails or returns no results.
    """
    try:
        url = f"https://api.viewdns.info/subdomains/?domain={domain}&apikey={VIEWDNS_API_KEY}&output=json"
        print(f"[*] Querying ViewDNS.info API for: {domain}")
        resp = requests.get(url, timeout=30)

        if resp.status_code == 200:
            data = resp.json()

            if data.get('response', {}).get('error'):
                error_msg = data['response']['error']
                print(f"[-] ViewDNS.info API Error: {error_msg}")
                return []

            subdomains_data = data.get('response', {}).get('subdomains', [])
            subdomains_list = []
            for entry in subdomains_data:
                sub_name = entry.get('name')
                if sub_name:
                    subdomains_list.append(sub_name)

            if not subdomains_list:
                print("[-] ViewDNS.info returned zero subdomains.")
                return []

            final_list = list(set(subdomains_list))
            print(f"[+] SUBS discovered {len(final_list)} subdomains via ViewDNS.info.")
            return final_list

        else:
            print(f"[-] ViewDNS.info API request failed with status code: {resp.status_code}")
            return []

    except requests.exceptions.RequestException as e:
        print(f"[-] Network error while contacting ViewDNS.info: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"[-] Failed to parse JSON response: {e}")
        return []
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        return []
