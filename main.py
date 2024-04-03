import yaml
import time
from copy import deepcopy
import csv
import time

import settings
import utils.log_handler as logger
log = logger.log
from utils.auth_handler import Auth
import utils.input_utils as input
import utils.general_utils as utils
import api


def get_parser_choice(parsers) -> int:
    """
    Prompts the user to select from a list of parsers to export related parser actions to CSV.
    Based on subsequently called functions, this will return a valid option or exit the script.

    :param repos: List of parsers returned from the GET Get Tenant Parsers endpoint
    :type repos: list[parser objects]
    :return: 0-based index of selected parser from the list provided
    :rtype: int
    """
    log.info(f'List of Parsers:')
    index = 1
    for parser in parsers:
        log.info(f'{index} - Name: {parser["name"]}')
        index += 1
    return input.user_list("Select a parser/scan tool to export parser actions from", "Invalid choice", len(parsers)) - 1

def get_page_of_parser_actions(parser_id: str, page: int = 0, actions: list = [], total_actions: int = -1) -> None:
    """
    Handles traversing pagination results to create a list of all items.

    :param page: page to start on, for all results use 0, defaults to 0
    :type page: int, optional
    :param assets: the list passed in will be added to, acts as return, defaults to []
    :type assets: list, optional
    :param total_assets: used for recursion to know when all pages have been gathered, defaults to -1
    :type total_assets: int, optional
    """
    log.info(f'Load page {page} of parser actions...')
    offset = page*1000
    limit = 1000
    # region EXAMPLE schema of returned parser actions
        # {
        #     "id": "10028",
        #     "action": "LINK",
        #     "severity": "Medium",
        #     "writeupID": "101219",
        #     "log_trail": [
        #         {
        #             "updated_by": {
        #                 "user_id": 13338,
        #                 "name": {
        #                     "first": "Jordan",
        #                     "last": "Treasure"
        #                 }
        #             },
        #             "updated_at": 1701906483227,
        #             "action": "LINK",
        #             "severity": "Medium",
        #             "writeupID": "11407137"
        #         }
        #     ],
        #     "title": "DNS Server BIND version Directive Remote Version Detection",
        #     "description": "The remote host is running BIND or another DNS server that reports its version number when it receives a special request for the text 'version.bind' in the domain 'chaos'. \n\nThis version is not necessarily accurate and could even be forged, as some DNS servers send the information based on a configuration file.\n",
        #     "writeup": {
        #         "description": "Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.\n",
        #         "doc_id": 101219,
        #         "doc_type": "template",
        #         "fields": {},
        #         "isDeleted": false,
        #         "id": "template_101219",
        #         "repositoryId": "cl6cg379h01km17lbeg713x1w",
        #         "recommendations": "If possible, applications should avoid incorporating user-controllable data into redirection targets. In many cases, this behavior can be avoided in two ways:\nRemove the redirection function from the application, and replace links to it with direct links to the relevant target URLs.\nMaintain a server-side list of all URLs that are permitted for redirection. Instead of passing the target URL as a parameter to the redirector, pass an index into this list.\n\nIf it is considered unavoidable for the redirection function to receive user-controllable input and incorporate this into the redirection target, one of the following measures should be used to minimize the risk of redirection attacks:\nThe application should use relative URLs in all of its redirects, and the redirection function should strictly validate that the URL received is a relative URL.\nThe application should use URLs relative to the web root for all of its redirects, and the redirection function should validate that the URL received starts with a slash character. It should then prepend http://yourdomainname.com to the URL before issuing the redirect.\nThe application should use absolute URLs for all of its redirects, and the redirection function should verify that the user-supplied URL begins with http://yourdomainname.com/ before issuing the redirect.\n\nStored open redirection vulnerabilities arise when the applicable input was submitted in an previous request and stored by the application. This is often more serious than reflected open redirection because an attacker might be able to place persistent input into the application which, when viewed by other users, causes their browser to invisibly redirect to a domain of the attacker's choice.\n",
        #         "references": "- Using Burp to Test for Open Redirections(https://support.portswigger.net/customer/portal/articles/1965733-Methodology_Testing%20for%20Open%20Redirections.html)\n- Fun With Redirects(https://www.owasp.org/images/b/b9/OWASP_Appsec_Research_2010_Redirects_XSLJ_by_Sirdarckcat_and_Thornmaker.pdf)\n\nCWE-601: URL Redirection to Untrusted Site ('Open Redirect')\n",
        #         "severity": "Medium",
        #         "source": "Burp",
        #         "tenantId": 0,
        #         "title": "Open redirection (stored)",
        #         "updatedAt": 1701714762104,
        #         "writeupAbbreviation": "DEF-1"
        #     },
        #     "original_severity": "Informational",
        #     "writeupLabel": "Open redirection (stored)"
        # }
    # endregion
    try:
        response = api.parser_actions.get_tenant_parser_actions(auth.base_url, auth.get_auth_headers(), auth.tenant_id, parser_id, limit, offset)
    except Exception as e:
        log.critical(f'Could not retrieve parser actions from instance. Exiting...')
        exit()
        
    total_actions = int(response.json['actions']['total_items'])
    if len(response.json['actions']['actions']) > 0:
        actions += deepcopy(response.json['actions']['actions'])
    
    if len(actions) < total_actions:
        return get_page_of_parser_actions(parser_id, page+1, actions, total_actions)
    
    return None



if __name__ == '__main__':
    for i in settings.script_info:
        print(i)

    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)

    auth = Auth(args)
    auth.handle_authentication()

    # load all plugins from instance
    log.info(f'Loading Parsers from instance')
    parsers = []
    try:
        response = api.parser_actions.get_tenant_parsers(auth.base_url, auth.get_auth_headers(), auth.tenant_id)
        parsers = response.json['parsers']
    except Exception as e:
        log.exception(e)

    # log.debug(f'list of loaded parsers:\n{parsers}')
    log.success(f'Loaded {len(parsers)} parser(s) from instance')
    if len(parsers) < 1:
        log.critical(f'Did not load any parsers from instance. Exiting...')
        exit()


    # prompt user to select a parser for export
    while True:
        choice = get_parser_choice(parsers)
        if input.continue_anyways(f'Export parser actions for \'{parsers[choice]["name"]}\' to CSV?'):
            break
    selected_parser = parsers[choice]


    # set file path for exported CSV
    parser_time_seconds: float = time.time()
    parser_time: str = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime(parser_time_seconds))
    FILE_PATH = f'{utils.sanitize_file_name(selected_parser["name"]).lower()}_parser_actions_export_{parser_time}.csv'


    # get all parser actions in user selected client
    log.info(f'Getting Parser Actions from selected Parser')
    loaded_parser_actions = []
    get_page_of_parser_actions(selected_parser['id'], 0, actions=loaded_parser_actions)
    log.debug(f'list of loaded parser actions:\n{loaded_parser_actions}')
    log.success(f'Loaded {len(loaded_parser_actions)} parser actions for {selected_parser["name"]}')


    # CREATE CSV
    # define headers
    headers = ["plugin_id", "title", "action", "severity", "original_severity", "description", "last_updated_at", "writeup_id", "writeup_title", "writeup_abbreviation", "writeup_repository_id"]

    # pluck parser action data from API response and format as list for CSV
    csv_parser_actions = []
    for parser_action in loaded_parser_actions:
        # last updated at - parsed from log_trail
        last_updated_at = ""
        if len(parser_action.get("log_trail", [])) > 0:
            updated_at_time_stamps = list(map(lambda x: x['updated_at'], parser_action.get("log_trail", [])))
            last_updated_at_ms = max(updated_at_time_stamps)
            last_updated_at = time.strftime("%b %d, %Y", time.gmtime(last_updated_at_ms/1000))
        # writeup fields - if there is an attached writeup
        writeup_id = parser_action.get("writeupID", "")
        if writeup_id == None:
            writeup_id = ""
        writeup_title = parser_action.get("writeupLabel", "")
        if writeup_title == None:
            writeup_title = ""
        writeup_abbreviation = ""
        repository_id = ""
        writeup = parser_action.get("writeup")
        if writeup != None:
            writeup_abbreviation = writeup.get("writeupAbbreviation", "")
            if writeup_abbreviation == None:
                writeup_abbreviation = ""
            repository_id = writeup.get("repositoryId", "")
            if repository_id == None:
                repository_id = ""
        # all fields
        fields_for_csv = [
            parser_action.get("id", ""),
            parser_action.get("title", ""),
            parser_action.get("action", ""),
            parser_action.get("severity", ""),
            parser_action.get("original_severity", ""),
            parser_action.get("description", ""),
            last_updated_at,
            writeup_id,
            writeup_title,
            writeup_abbreviation,
            repository_id
        ]

        # add parser action to list to be written to csv
        csv_parser_actions.append(fields_for_csv)

    # WRITE CSV
    with open(FILE_PATH, 'w', newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(csv_parser_actions)
    log.success(f'Saved parser actions to CSV \'{FILE_PATH}\'')
