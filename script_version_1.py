import re
import requests
import time
import json

exception_list = open('exceptions.txt', 'r').readlines()  # List of whitelisted vulnerable domains
vuln_list = []  # List of vulnerable domains needed to show

# print(ready_list)


def remove_duplicates(list_: list):
    items_number = len(list_)
    black_list = []  # Black list where duplicates will be stored
    for searched_one in range(items_number):  # Search each element in this list for duplicates and store it in black
        for it in range(items_number):
            if searched_one < it and list_[searched_one] is list_[it]:  # it must be in front of searched_one for no dup
                black_list.append(list_[searched_one])
    for it in range(len(black_list)):  # Delete all first found duplicate blacklisted value from list_
        if black_list[it] in list_:
            list_.remove(black_list[it])


###############################################################################################################
############################# DEFINITION OF FUNCTION OF VIRUSTOTAL API ########################################
###############################################################################################################
def return_response(domain):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey': 'YOUR API KEY IS HERE', 'domain': domain}
    response_ = requests.get(url, params=params, verify=False).json()
    time.sleep(30)
    return response_


###############################################################################################################

# Vizvat funkciyu v funkcii dlya rekursivnogo poiska vredonosnix domenov

###############################################################################################################
############################# DEFINITION OF FUNCTION OF RECURSIVE SEARCH IN SUBDOMAINS ########################
###############################################################################################################
def search_threat(domain_list: list):
    global vuln_list
    for domain in range(len(domain_list)):  # For each domain in list -
        response_: dict = return_response(domain_list[domain])  # Return dict response from virustotal (function heart)
        if threat_isfound(response_) and domain_list[domain] not in exception_list:
            vuln_list.append(domain_list[domain])  # Append domain to list
        elif 'subdomains' in response_.keys() and response_['subdomains'] is not []:  # If domain have subdomains
            search_threat(response_['subdomains'])  # Recurse function and find threat in subdomains


###############################################################################################################

# Nayti ugrozu v domene/subdomene

###############################################################################################################
############################# DEFINITION OF FUNCTION OF FINDING THREAT IN DOMAIN/SUBDOMAIN ####################
###############################################################################################################
def threat_isfound(dict_response: dict):
    web_reputation = ['safe', 'unsure']
    if 'Webutation domain info' in dict_response.keys() and dict_response['Webutation domain info']['Verdict'] not in web_reputation\
            or 'detected_downloaded_samples' in dict_response.keys() and dict_response['detected_downloaded_samples'] != []\
            or 'detected_urls' in dict_response.keys() and dict_response['detected_urls'] != []\
            or 'detected_communicating_samples' in dict_response.keys() and dict_response['detected_communicating_samples'] != []:
        return True
    else:
        return False


################################################################################################################

# Send founded vulnerable domain info to Slack via API

################################################################################################################
############################DEFINITION OF FUNCTION FOR SENDING DOMAINS TO SLACK ###############################
################################################################################################################
def sendTo_slack(vulnerable_list: list):
    url = 'YOUR SLACK LINK IS HERE'

    vulnerable_string = ', '.join(vulnerable_list)
    data = {"text": "Dangerous domains are: " + vulnerable_string}
    json_data = json.dumps(data)
    requests.post(url, json_data)


ready_list = open('domains.txt', 'r').readlines()  # Take file as a list of domains
for item in range(len(ready_list)):  # Clean the ^ and * to the dot
    ready_list[item] = re.sub(r'^.*[\^*]+\.', '', ready_list[item])
for item in range(len(ready_list)):  # Clean the \n at the end of each line
    ready_list[item] = ready_list[item].rstrip('\n')




# search_threat(ready_list)
# remove_duplicates(vuln_list)
# sendTo_slack(vuln_list)
