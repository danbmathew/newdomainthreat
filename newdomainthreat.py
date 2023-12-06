import os
import base64
import datetime
import sys
import zipfile
from io import BytesIO
import requests
import tldextract
import textdistance
from detectidna import unconfuse
import unicodedata

list_file_domains = []
keywords = ['kanoo']   #input only lower case keywords into this list

desktop = os.path.join(os.path.expanduser('~'), 'newdomainthreat')
daterange = datetime.datetime.today() - datetime.timedelta(days=1)
previous_date = daterange.strftime('20%y-%m-%d')
today = datetime.date.today()
previous_date_formated = previous_date + '.zip'
this_new = base64.b64encode(previous_date_formated.encode('ascii'))
#domain_file = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(this_new.decode('ascii'))
domain_file = 'https://www.whoisds.com//whois-database/newly-registered-domains/MjAyMy0xMi0wMi56aXA=/nrd'
request = requests.get(domain_file)
zipfiles = zipfile.ZipFile(BytesIO(request.content))
zipfiles.extractall(desktop)
file_domains = open(f'{desktop}/domain-names.txt', 'r', encoding='utf-8-sig')

def damerau(keyword, domain):
        damerau_value = textdistance.damerau_levenshtein(keyword, domain)
        if 4 <= len(keyword) <= 6:
            if damerau_value <= 1:
                return domain
        elif 6 <= len(keyword) <= 9:
            if damerau_value <= 2:
                return domain
        elif len(keyword) >= 10:
            if damerau_value <= 3:
                return domain

def jaccard(keyword, domain, n_gram):
        domain_letter_weight = '#' + domain + '#'
        keyword_letter_weight = '#' + keyword + '#'
        ngram_keyword = [keyword_letter_weight[i:i + n_gram] for i in range(len(keyword_letter_weight) - n_gram + 1)]
        ngram_domain_name = [domain_letter_weight[i:i + n_gram] for i in range(len(domain_letter_weight) - n_gram + 1)]
        intersection = set(ngram_keyword).intersection(ngram_domain_name)
        union = set(ngram_keyword).union(ngram_domain_name)
        similarity = len(intersection) / len(union) if len(union) > 0 else 0
        if similarity > 0.5:
            return domain

def jaro_winkler(keyword, domain):
    winkler = textdistance.jaro_winkler.normalized_similarity(keyword, domain)
    if winkler >= 0.9:
        return domain

def lcs(keyword, domain, keywordthreshold):
    longest_common_substring = ""
    max_length = 0
    for i in range(len(keyword)):
        if keyword[i] in domain:
            for j in range(len(keyword), i, -1):
                if keyword[i:j] in domain:
                    if len(keyword[i:j]) > max_length:
                        max_length = len(keyword[i:j])
                        longest_common_substring = keyword[i:j]
    if ((len(longest_common_substring) / len(keyword)) > keywordthreshold and (len(longest_common_substring) is not len(keyword))):
        return domain

for each in keywords:
    for my_domains in file_domains:
        domain_name = tldextract.extract(my_domains.replace("\n", "").lower().strip()).domain
        if (damerau(each, domain_name) is not None):
            list_file_domains.append(my_domains)
        if (jaccard(each, domain_name, 2) is not None):
            list_file_domains.append(my_domains)
        if (jaro_winkler(each, domain_name) is not None):
            list_file_domains.append(my_domains)

        if unconfuse(domain_name) is not domain_name:
            latin_domain = unicodedata.normalize('NFKD', unconfuse(domain_name)).encode('latin-1', 'ignore').decode('latin-1')
            if (damerau(each, latin_domain) is not None):
                list_file_domains.append(my_domains)
            if (jaccard(each, latin_domain, 2) is not None):
                list_file_domains.append(my_domains)
            if (jaro_winkler(each, latin_domain) is not None):
                list_file_domains.append(my_domains)

        if (len(each)>8):
            if(lcs(each, domain_name, 0.5) is not None):
                list_file_domains.append(my_domains)

final_list = set(list_file_domains)
for item in final_list:
    print(item.replace("\n", "").lower().strip())








        

