"""
Auther: Amol Pandhare
Email: pandhareamol96@gmail.com
"""

import re
import requests
import logging # Not having log files for this script.
import argparse
from bs4 import BeautifulSoup
from prettytable import PrettyTable
import datetime

abuseipdb_headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
virustotal_headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0','Accept':'application/json','Accept-Language':'en-US,en;q=0.5','Accept-Encoding':'gzip, deflate','content-type':'application/json','X-Tool':'vt-ui-main','x-app-version':'v1x52x1','Accept-Ianguage':'en-US,en;q=0.9,es;q=0.8','Sec-Fetch-Dest':'empty','Sec-Fetch-Mode':'cors','Sec-Fetch-Site':'same-origin','Referer':'https://www.virustotal.com/','X-VT-Anti-Abuse-Header':'MTQ0MTIxNDQ5OTgtWkc5dWRDQmlaU0JsZG1scy0xNjM3MTUzNDMzLjUwNQ==','Cookie':'_ga=GA1.2.1301540161.1628839274; _gid=GA1.2.631260150.1637128398; _gat=1'}

REGEX_abuseipdb = re.compile(r"This IP was reported\s(\d+)\stimes.\sConfidence of Abuse is (\d+).*")
dict_engine_urls = {'abuseipdb':['https://www.abuseipdb.com/check/{}', abuseipdb_headers],
                    'virustotal':['https://www.virustotal.com/ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={}',virustotal_headers]}

ip_headers = ['Sr. No.','Engine','Found','Confidance','Reported Count','Other Details']

pt = PrettyTable()

def get_html_response(ip_address, engine_details):
    """
    Function to get the html response from abuseipdb
    """
    if not ip_address:
        return False
    try:
        response = requests.get(engine_details[0].format(ip_address), headers = engine_details[1])
    except Exception as ex:
        logging.error(f"Exception while getting html responce for ip: {ip_address}, Error: {ex}")
        return False

    if response.status_code != 200:
        logging.error(f"Status code: {response.status_code}, Message: {response.text}")
        return False

    return response

def get_abuseipdb_intel(http_response):
    """
    Function to get the malicious confidence and number of
    times ip is reported malicious by various vendors.
    """
    results = dict()
    try:
        raw_html = http_response.text
    except Exception as ex:
        print("[-] Can't collect details from abuseipdb.")
        return results

    results = dict()
    other_details = ''
    soup = BeautifulSoup(raw_html, 'html5lib')
    details = soup.find('div', attrs={'class':'well'})

    if 'was found in our database' in details.text:
        match = re.match(REGEX_abuseipdb, details.find('p').text.replace(',',''))
        reported_count = int(match.group(1))
        confidance     = int(match.group(2))
        results.update({'engine':'abuseipdb',
            'found':'yes',
            'reported_count':reported_count,
            'confidance':confidance})

        # Looking for summary and last reported time
        report_wrapper = soup.find('section',attrs={'id':'report-wrapper'})
        para = report_wrapper.find_all('p')
        paragraph = para[2].text.replace(',','\n')

        # Appending summary to other_details
        other_details += 'Summary: {}'.format(paragraph)

        # Collecting attack categories
        categories = set()
        attk_categories = soup.find_all('td', attrs = {'data-title':'Categories'})
        for c in attk_categories:
            categories.update(c.text.split('\n'))
        categories.remove('')
        other_details += f'Categories: {",".join(list(categories))}'


    # Collecting other details like country, owner, city etc.
    table = details.find('tbody')
    list_ = table.text.split('\n')
    c = 0
    for i in list_:
        if i == '':
            continue
        if c%2 == 0:
            other_details+= f'{i}:'
        else:
            other_details+= f'{i}\n'
        c+=1

    results.update({'other_details':other_details})

    return results

def get_virustotal_intel(http_response):
    """
    Function to parse the http response from virus total and
    collect ip intel.
    """
    results = dict()
    try:
        data_dict = http_response.json()
    except Exception as ex:
        print("[-] Can't collect intell from virus Total.")
        return results

    if not data_dict:
        return results

    cnt = int(data_dict['data'][0]['attributes']['last_analysis_stats']['malicious']) + int(data_dict['data'][0]['attributes']['last_analysis_stats']['suspicious'])
    reported_count = "{}/{}".format(cnt,sum(data_dict['data'][0]['attributes']['last_analysis_stats'].values()))
    confidance = '-'
    country = data_dict['data'][0]['attributes']['country']
    owner = data_dict['data'][0]['attributes']['as_owner']
    asn = data_dict['data'][0]['attributes']['asn']
    engines = ''
    all_details = data_dict['data'][0]['attributes']['last_analysis_results']
    for k,v in all_details.items():
        if v['category'] == 'malicious':
            engines += f'{k},'
    engines =  engines.replace(',','')

    date_ = '-'
    if 'last_modification_date' in data_dict['data'][0]['attributes']:
        last_modification_date = data_dict['data'][0]['attributes']['last_modification_date']
        date_ = datetime.datetime.fromtimestamp(last_modification_date).strftime('%Y-%m-%d %H:%M:%S')

    other_details = f"Country: {country}\nOwner: {owner}\nASN: {asn}\nLastModificationDate: {date_}\nEngines: {engines}"

    results.update({'engine':'abuseipdb',
            'found':'yes',
            'reported_count':reported_count,
            'confidance':confidance,
            'other_details': other_details})

    return results

def collect_intel(ip_address):
    """
    Function to collect intel from all the engines.
    """
    #pdb.set_trace()
    cnt = 1
    for k , v in dict_engine_urls.items():
        res = get_html_response(ip_address, v)
        intel = None
        if k == 'abuseipdb':
            intel = get_abuseipdb_intel(res)
        if k == 'virustotal':
            intel = get_virustotal_intel(res)

        pt.add_row([cnt,
            k,
            intel['found'] if intel and 'found' in intel else 'No',
            intel['confidance'] if intel and 'confidance' in intel else '-',
            intel['reported_count'] if intel and 'reported_count' in intel else '-',
            intel['other_details'] if intel and 'other_details' in intel else '-'])
        cnt += 1
        pt.add_row(['','','','','',''])

if __name__ == '__main__':
    #pdb.set_trace()
    parser = argparse.ArgumentParser(prog='Check IP Reputation', description='Ip reputation check from multiple sources')
    parser.add_argument('-i',dest='ip',help='Ip address')

    args = parser.parse_args()

    if args.ip:
        pt.field_names = ip_headers
        collect_intel(args.ip)
        pt.get_string(title="Intel for IP: {}".format(args.ip))
        pt.align['Other Details'] = "l"
        ll = "+-------------------------------------------+"
        ip_ = f"| IP: {args.ip}                                 "
        print(ll)
        print(ip_[0:(len(ll)-1)]+'|')
        print(ll)

    print(pt)
