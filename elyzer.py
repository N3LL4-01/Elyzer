import sys
from argparse import ArgumentParser
import re
from colorama import init as colorama_init
from colorama import Fore
import dns.resolver
import requests
import json
from datetime import datetime
from email.parser import BytesParser
import ipaddress
from email.header import decode_header
import hashlib

def getReceivedFields(eHeader):
    found = False
    tmp = ''
    receivedFields =[]
    finalReceivedFields = []
    fields = getFields(eHeader)

    with open(eHeader, 'r', encoding='UTF-8') as header:
        for lines in header:
            separator = lines.split()
            
            if len(separator) != 0 and separator[0] in fields and found:
                receivedFields.append(tmp)
                tmp =''
                if separator[0] != 'Received:':
                    found = False            
                else:
                    tmp += lines
            elif found:
                tmp += lines
            elif 'Received:' in lines.split():
                found = True
                tmp += lines

    for x in receivedFields:
        finalReceivedFields.append(' '.join(x.split()))

    return finalReceivedFields

def getFields(filename):
    fields = []
    with open(filename, "rb") as fp:
        headers = BytesParser().parse(fp)
    for j in headers:
        fields.append(j + ":")
    return fields

def resolveIP(domain, passive=False):
    if passive:
        print(f'{Fore.LIGHTYELLOW_EX}Skipping DNS resolution for {domain} due to passive mode.{Fore.RESET}')
        return 'Passive DNS lookup skipped'
    try:
        resolve4 = dns.resolver.resolve(domain, 'A')
        if resolve4:
            for resolved4 in resolve4:
                return f'{resolved4}'
    except Exception as e:
        return f'{Fore.LIGHTRED_EX}Error: {e}.{Fore.RESET}'


def passive_dns_query(domain, api_key):
    url = f"https://api.passivetotal.org/v2/dns/passive?query={domain}"
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if data['success']:
            for record in data['results']:
                if record['resolveType'] == 'A':
                    return record['resolve']
    except Exception as e:
        print(f'{Fore.LIGHTRED_EX}Passive DNS query failed: {e}{Fore.RESET}')
    return None

def routing(eHeader):
    routing =[]
    counter= 0

    print(f'\n{Fore.LIGHTBLUE_EX}Relay Routing: {Fore.RESET}')
    routing.append(f'Relay Routing:\n')

    for y in reversed(getReceivedFields(eHeader)):
        receivedMatch = re.findall(r'received: from ([\w\-.:]+)', y, re.IGNORECASE)
        byMatch = re.findall(r'by ([\w\-.:]+)', y, re.IGNORECASE)
        withMatch = re.findall(r'with ([\w\-.:]+)', y, re.IGNORECASE)

        counter += 1 
        try:
            if len(receivedMatch) != 0:
                print(f'Hop {counter} |↓|: FROM {Fore.GREEN}{receivedMatch[0].lower()}{Fore.RESET} TO {Fore.GREEN}{byMatch[0].lower()}{Fore.RESET} WITH {Fore.CYAN}{withMatch[0].lower()}{Fore.RESET}')
                routing.append(f'Hop {counter} |↓|: FROM {receivedMatch[0].lower()} TO {byMatch[0].lower()} WITH {withMatch[0].lower()}\n')
            else:
                print(f'{Fore.LIGHTYELLOW_EX}No match found for Hop {counter}{Fore.RESET}')
        except Exception as e:
            print(f'{Fore.LIGHTRED_EX}Error: {e}. Skipping...{Fore.RESET}')
      
    print(f'\n{Fore.LIGHTBLUE_EX}Timestamps between Hops: {Fore.RESET}')
    routing.append(f'\nTimestamps between Hops:\n')

    dateCounter = 1
    prevTimestamp = None
    delta = None

    for x in reversed(getReceivedFields(eHeader)):
        dateMatch1 = re.findall(r'\S{3},[ ]{0,4} \d{1,2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2} [+-]\d{4}', x ,re.IGNORECASE)
        dateMatch2 = re.findall(r'\S{3}, \d{2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)
        dateMatch3 = re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)

        if dateMatch1 is not None:
            for date in reversed(dateMatch1):
                currentTimeStamp = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z')
                if prevTimestamp:
                    delta = currentTimeStamp - prevTimestamp
                    print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}, {Fore.CYAN}Delta: {delta}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}, Delta: {delta if delta is not None else "N/A"}\n')
                dateCounter += 1
                prevTimestamp = currentTimeStamp
        
        elif dateMatch2 is not None:
            for date in reversed(dateMatch2):
                currentTimeStamp = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S.%f %z')
                if prevTimestamp:
                    delta = currentTimeStamp - prevTimestamp
                    print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}, {Fore.CYAN}Delta: {delta}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}, Delta: {delta if delta is not None else "N/A"}\n')
                dateCounter += 1
                prevTimestamp = currentTimeStamp

        elif dateMatch3 is not None:
            for date in reversed(dateMatch3):
                currentTimeStamp = datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f %z')
                if prevTimestamp:
                    delta = currentTimeStamp - prevTimestamp
                    print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}, {Fore.CYAN}Delta: {delta}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}\n, Delta: {delta if delta is not None else "N/A"}\n')
                dateCounter += 1
                prevTimestamp = currentTimeStamp

    return ''.join(routing)

def generalInformation(eheader):
    gInformation = []

    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    subject = content.get('subject')
    if subject is not None:
        decoded_subject = decode_header(subject)
        decodedHeader = ''
        for part, charset in decoded_subject:
            try:
                if isinstance(part, bytes):
                    decodedHeader += part.decode(charset or 'utf8')
                else:
                    decodedHeader += part
            except (LookupError, UnicodeDecodeError):
                decodedHeader += part.decode('iso-8859-1') if isinstance(part, bytes) else part
    else:
        decodedHeader = None
    
    print(f'\n{Fore.LIGHTBLUE_EX}General Information: {Fore.RESET}')
    gInformation.append(f'\nGeneral Information:\n')

    print(f'From: {Fore.GREEN}{content["from"]}{Fore.RESET}')
    print(f'To: {Fore.GREEN}{content["to"]}{Fore.RESET}')
    print(f'Subject: {Fore.GREEN}{decodedHeader}{Fore.RESET}')
    print(f'Date: {Fore.GREEN}{content["date"]}{Fore.RESET}')

    gInformation.append(f'From: {content["from"]}\n' + f'To: {content["to"]}\n' + f'Subject: {decodedHeader}\n' + f'Date: {content["date"]}\n')
    
    return ''.join(gInformation)


def securityInformations(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    secInfos = []

    print(f'\n{Fore.LIGHTBLUE_EX}Security Informations: {Fore.RESET}')
    secInfos.append(f'\nSecurity Informations:\n')

    if content['received-spf'] is not None:
        if 'fail' in content['received-spf'].lower():
            print(f'Received SPF: {Fore.LIGHTRED_EX}{content["received-spf"]}{Fore.RESET}')
            secInfos.append(f'Received SPF: {content["received-spf"]}')
        
        elif 'None' in content['received-spf']:
            print(f'Received SPF: {Fore.LIGHTRED_EX}{content["received-spf"]}{Fore.RESET}')
            secInfos.append(f'Received SPF: {content["received-spf"]}')

        else:
            print(f'Received SPF: {Fore.GREEN}{content["received-spf"]}{Fore.RESET}')
            secInfos.append(f'Received SPF: {content["received-spf"]}')
    else:
        print(f'Received SPF: {Fore.LIGHTRED_EX}No Received SPF{Fore.RESET}')


    if content['dkim-signature'] is not None:
        print(f'DKIM Signature: {Fore.GREEN}{content["dkim-signature"]}{Fore.RESET}')
        secInfos.append(f'DKIM Signature: {content["dkim-signature"]}')
    else:
        print(f'DKIM Signature: {Fore.LIGHTRED_EX}No DKIM Signature{Fore.RESET}')
        secInfos.append(f'DKIM Signature: No DKIM Signature')
    

    if content['dmarc'] is not None:
        print(f'DMARC: {Fore.GREEN}{content["dmarc"]}{Fore.RESET}')
        secInfos.append(f'DMARC: {content["dmarc"]}')
    else:
        print(f'DMARC: {Fore.LIGHTRED_EX}No DMARC{Fore.RESET}')
        secInfos.append(f'DMARC: No DMARC')
    

    if content['authentication-results'] is not None:
        if 'spf=fail' in content['authentication-results'].lower():
            print(f'Authentication Results: {Fore.LIGHTRED_EX}{content["authentication-results"]}{Fore.RESET}')
            secInfos.append(f'Authentication Results: {content["authentication-results"]}')
        else:
            print(f'Authentication Results: {Fore.GREEN}{content["authentication-results"]}{Fore.RESET}')
            secInfos.append(f'Authentication Results: {content["authentication-results"]}')
            
    else:
        print(f'Authentication Results: {Fore.LIGHTRED_EX}No Authentication Results{Fore.RESET}')
        secInfos.append(f'Authentication Results: No Authentication Results')

    
    if content['x-forefront-antispam-report'] is not None:
        print(f'X-Forefront-Antispam-Report: {Fore.GREEN}{content["x-forefront-antispam-report"]}{Fore.RESET}')
        secInfos.append(f'X-Forefront-Antispam-Report: {content["x-forefront-antispam-report"]}')
    else:
        print(f'X-Forefront-Antispam-Report: {Fore.LIGHTRED_EX}No X-Forefront-Antispam-Report{Fore.RESET}')
        secInfos.append(f'X-Forefront-Antispam-Report: No X-Forefront-Antispam-Report')


    if content['x-microsoft-antispam'] is not None:
        print(f'X-Microsoft-Antispam: {Fore.GREEN}{content["x-microsoft-antispam"]}{Fore.RESET}')
        secInfos.append(f'X-Microsoft-Antispam: {content["x-microsoft-antispam"]}')
    else:
        print(f'X-Microsoft-Antispam: {Fore.LIGHTRED_EX}No X-Microsoft-Antispam{Fore.RESET}')
        secInfos.append(f'X-Microsoft-Antispam: No X-Microsoft-Antispam')

    return '\n'.join(secInfos)

def envelope(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    eenvelope = []

    print(f'\n{Fore.LIGHTBLUE_EX}Interesting Headers: {Fore.RESET}')
    eenvelope.append(f'\nInteresting Headers:\n')

    if content['X-ORIG-EnvelopeFrom'] is not None:
        fromMatch = re.search(r'<(.*)>', content['from'])

        if content['X-ORIG-EnvelopeFrom'] == 'anonymous@':
            print(f'{Fore.LIGHTRED_EX}Envelope From: {Fore.LIGHTYELLOW_EX}{content["X-ORIG-EnvelopeFrom"]}{Fore.RESET}')
            eenvelope.append(f'Envelope From: {content["X-ORIG-EnvelopeFrom"]}')
        
        elif content['X-ORIG-EnvelopeFrom'] != fromMatch.group(1):
            print(f'{Fore.RED}POTENTIAL SPOOFING ATTACK DETECTED: FROM ({content["from"]}) NOT EQUAL ({content["X-ORIG-EnvelopeFrom"]}){Fore.RESET}')
            eenvelope.append(f'POTENTIAL SPOOFING ATTACK DETECTED: FROM ({content["from"]}) NOT EQUAL ({content["X-ORIG-EnvelopeFrom"]})')

        else:
            print(f'Envelope From: {Fore.GREEN}{content["X-ORIG-EnvelopeFrom"]}{Fore.RESET}')
            eenvelope.append(f'Envelope From: {content["X-ORIG-EnvelopeFrom"]}')
    else:
        print(f'Envelope From: {Fore.LIGHTRED_EX}No Envelope From{Fore.RESET}')
        eenvelope.append(f'Envelope From: No Envelope From')


    if content['return-path'] is not None:
        print(f'Return Path: {Fore.GREEN}{content["return-path"]}{Fore.RESET}')
        eenvelope.append(f'Return Path: {content["return-path"]}')
    else:
        print(f'Return Path: {Fore.LIGHTRED_EX}No Return Path{Fore.RESET}')
        eenvelope.append(f'Return Path: No Return Path')

    if content['message-id'] is not None:
        print(f'Message ID: {Fore.GREEN}{content["message-id"]}{Fore.RESET}')
        eenvelope.append(f'Message ID: {content["message-id"]}')
    else:
        print(f'Message ID: {Fore.LIGHTRED_EX}No Message ID{Fore.RESET}')
        eenvelope.append(f'Message ID: No Message ID')

    if content['mime-version'] is not None:
        print(f'MIME-Version: {Fore.GREEN}{content["mime-version"]}{Fore.RESET}')
        eenvelope.append(f'MIME-Version: {content["mime-version"]}')
    else:
        print(f'MIME-Version: {Fore.LIGHTRED_EX}No MIME-Version{Fore.RESET}')
        eenvelope.append(f'MIME-Version: No MIME-Version')

    if content['authentication-results-original'] is not None:
        if 'spf=fail' in content['authentication-results-original'].lower():
            print(f'Authentication-Results-Original: {Fore.LIGHTRED_EX}{content["authentication-results-original"]}{Fore.RESET}')
            eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
        
        elif 'spf=pass' in content['authentication-results-original'].lower():
            print(f'Authentication-Results-Original: {Fore.GREEN}{content["authentication-results-original"]}{Fore.RESET}')
            eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
        
        else:
            print(f'Authentication-Results-Original: {Fore.LIGHTYELLOW_EX}{content["authentication-results-original"]}{Fore.RESET}')
            eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
    else:
        print(f'Authentication-Results-Original: {Fore.LIGHTRED_EX}No Authentication-Results-Original{Fore.RESET}')
        eenvelope.append(f'Authentication-Results-Original: No Authentication-Results-Original')


    print(f'{Fore.CYAN}\n<---------MS Exchange Organization Headers--------->\n{Fore.RESET}')
    eenvelope.append(f'\n<---------MS Exchange Organization Headers--------->\n')

    if content['x-ms-exchange-organization-authas'] is not None:
        if 'anonymous' or 'Anonymous' in content['x-ms-exchange-organization-authas']:
            print(f'X-MS-Exchange-Organization-AuthAs: {Fore.LIGHTYELLOW_EX}{content["x-ms-exchange-organization-authas"]}{Fore.RESET}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: {content["x-ms-exchange-organization-authas"]}')
        else:
            print(f'X-MS-Exchange-Organization-AuthAs: {Fore.GREEN}{content["x-ms-exchange-organization-authas"]}{Fore.RESET}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: {content["x-ms-exchange-organization-authas"]}')
    else:
        print(f'X-MS-Exchange-Organization-AuthAs: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthAs{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: No X-MS-Exchange-Organization-AuthAs')

    if content['x-ms-exchange-organization-authsource'] is not None:
        print(f'X-MS-Exchange-Organization-AuthSource: {Fore.GREEN}{content["x-ms-exchange-organization-authsource"]}{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthSource: {content["x-ms-exchange-organization-authsource"]}')
    else:
        print(f'X-MS-Exchange-Organization-AuthSource: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthSource{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthSource: No X-MS-Exchange-Organization-AuthSource')

    if content['x-ms-exchange-organization-authmechanism'] is not None:
        print(f'X-MS-Exchange-Organization-AuthMechanism: {Fore.GREEN}{content["x-ms-exchange-organization-authmechanism"]}{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthMechanism: {content["x-ms-exchange-organization-authmechanism"]}')
    else:
        print(f'X-MS-Exchange-Organization-AuthMechanism: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthMechanism{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthMechanism: No X-MS-Exchange-Organization-AuthMechanism')

    if content['x-ms-exchange-organization-network-message-id'] is not None:
        print(f'X-MS-Exchange-Organization-Network-Message-Id: {Fore.GREEN}{content["x-ms-exchange-organization-network-message-id"]}{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-Network-Message-Id: {content["x-ms-exchange-organization-network-message-id"]}')
    else:
        print(f'X-MS-Exchange-Organization-Network-Message-Id: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-Network-Message-Id{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-Network-Message-Id: No X-MS-Exchange-Organization-Network-Message-Id')
    
    print(f'{Fore.CYAN}\n<-------------------------------------------------->\n{Fore.RESET}')
    eenvelope.append(f'\n<-------------------------------------------------->\n')

    return '\n'.join(eenvelope)

import re
import ipaddress

def spoofing(eheader, passive=False):
    report = []

    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    print(f'\n{Fore.LIGHTBLUE_EX}Spoofing Check: {Fore.RESET}')
    report.append(f'\nSpoofing Check:\n')

    received_fields = getReceivedFields(eheader)
    if not received_fields:
        print(f'{Fore.RED}No received fields found in the email header.{Fore.RESET}')
        report.append('No received fields found in the email header.\n')
        return ''.join(report)

    x = next(iter(reversed(received_fields)), None)
    if not x:
        print(f'{Fore.RED}No received field to analyze.{Fore.RESET}')
        report.append('No received field to analyze.\n')
        return ''.join(report)

    ipv4 = re.findall(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]', x, re.IGNORECASE)
    ipv6 = re.findall(r'[\[\(]([A-Fa-f0-9:]+)[\]\)]', x, re.IGNORECASE)
    filteredIpv4 = [ip for ip in ipv4 if not ipaddress.ip_address(ip).is_private]

    formatReturnPath = False
    formatReplyTo = False
    
    fromMatch = re.search(r'<(.*)>', content['from'])
    if content['return-path'] is not None:
        if '<' in content['return-path']:
            returnToPath = re.search(r'<(.*?)>', content['return-path'])
            formatReturnPath = True
    if content['reply-to'] is not None:
        if '<' in content['reply-to']:
            replyTo = re.search(r'<(.*)>', content['reply-to'])
            formatReplyTo = True

    mx = []
    messageIDMx = []
    aRecordsOfMx = []

    mxAuthResult = []
    aRecordsOfMxAuthResult = []
    authResultOrigIP = None

    fromEmailDomain = fromMatch.group(1).split('@')[1]
    if not passive:
        try:
            getMx = dns.resolver.resolve(fromEmailDomain, 'MX')
            for servers in getMx:
                mx.append(servers.exchange.to_text().lower())

        except (dns.resolver.LifetimeTimeout, dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.YXDOMAIN,dns.resolver.NoNameservers) as e:
            print(f'{Fore.LIGHTRED_EX}Could not resolve the MX Record: {e}{Fore.RESET}')
            report.append(f'Could not resolve the MX Record: {e}\n')
        for servers in mx:
            resolved_ip = resolveIP(servers, passive)
            if resolved_ip != f'{Fore.LIGHTRED_EX}Error.{Fore.RESET}':
                aRecordsOfMx.append(resolved_ip)
            else:
                print(f'{Fore.LIGHTRED_EX}Error resolving IP for MX server: {servers}{Fore.RESET}')
                report.append(f'Error resolving IP for MX server: {servers}\n')
        
        if not aRecordsOfMx:
            print(f'{Fore.LIGHTRED_EX}No A records found for MX servers.{Fore.RESET}')
            report.append('No A records found for MX servers.\n')
    
    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for SMTP Server Mismatch...{Fore.RESET}')
    report.append('\nChecking for SMTP Server Mismatch...\n')  

    if filteredIpv4:
        if passive:
            print(f'{Fore.LIGHTYELLOW_EX}Passive mode enabled, skipping detailed SMTP server mismatch check.{Fore.RESET}')
            report.append(f'Passive mode enabled, skipping detailed SMTP server mismatch check.\n')
        elif filteredIpv4[0] in aRecordsOfMx:
            print(f'{Fore.LIGHTGREEN_EX}No Mismatch detected.{Fore.RESET}')
            report.append(f'No Mismatch detected.')
        else:
            print(f'{Fore.LIGHTYELLOW_EX}Potential SMTP Server Mismatch detected. Sender SMTP Server is "{fromEmailDomain} [{"".join(filteredIpv4[0])}]" and should be "{fromEmailDomain} [{", ".join(aRecordsOfMx)}]" <- (current MX Record(s) for this domain.) {Fore.RESET}')
            report.append(f'Potential SMTP Server Mismatch detected. Sender SMTP Server is "{fromEmailDomain} [{"".join(filteredIpv4[0])}]" and should be "{fromEmailDomain} [{", ".join(aRecordsOfMx)}]" <- (current MX Record(s) for this domain.)')
    else:
        if isinstance(content['Authentication-Results-Original'], str):
            authResultsOrigin = re.findall(r'sender IP is ([\d.]+)', content['Authentication-Results-Original'], re.IGNORECASE)
            if authResultsOrigin:
                ipv4 = authResultsOrigin
                authResultOrigIP = [ip for ip in ipv4 if not ipaddress.ip_address(ip).is_private]
                try:
                    authResultOrigDomain = dns.resolver.resolve(dns.reversename.from_address(''.join(authResultOrigIP)), 'PTR')
                    for domain in authResultOrigDomain:
                        authResultOrig = domain.to_text().lower()
                except (dns.resolver.LifetimeTimeout, dns.resolver.NoAnswer) as e:
                    print(f'{Fore.LIGHTRED_EX}Could not resolve the Domain Name: {e}{Fore.RESET}')
                    report.append(f'Could not resolve the Domain Name: {e}\n')      

                tmp = authResultOrig.split('.')
                authResultFullDomain = '.'.join(tmp[-3:-1])
                try:
                    authResultMx = dns.resolver.resolve(authResultFullDomain, 'MX')
                    for servers in authResultMx:
                        mxAuthResult.append(servers.exchange.to_text().lower())
                except dns.resolver.LifetimeTimeout as e:
                    print(f'{Fore.LIGHTRED_EX}Could not resolve the MX Record: {e}{Fore.RESET}')
                    report.append(f'Could not resolve the MX Record: {e}\n')

                for n in mxAuthResult:
                    resolved_ip = resolveIP(n, passive)
                    if resolved_ip != f'{Fore.LIGHTRED_EX}Error.{Fore.RESET}':
                        aRecordsOfMxAuthResult.append(resolved_ip)
                    else:
                        print(f'{Fore.LIGHTRED_EX}Error resolving IP for Auth Result MX server: {n}{Fore.RESET}')
                        report.append(f'Error resolving IP for Auth Result MX server: {n}\n')
                if any(x in aRecordsOfMxAuthResult for x in aRecordsOfMx):
                    print(f'{Fore.LIGHTGREEN_EX}No Mismatch detected.{Fore.RESET}')
                    report.append(f'No Mismatch detected.')
                else:
                    print(f'{indent}{Fore.LIGHTYELLOW_EX}No IPv4 Address detected in "FROM" Field. Doing additional checks...{Fore.RESET}')
                    report.append(f'{indent}No IPv4 Address detected in "FROM" Field. Doing additional checks...')
                    txtRecords = []
                    try:
                        authResultSpf = dns.resolver.resolve(authResultFullDomain, 'TXT')
                        for spf in authResultSpf:
                            authResultSpf = spf.to_text().lower()
                            txtRecords.append(re.findall(r'"(.*?)"', authResultSpf))
                    except dns.resolver.LifetimeTimeout as e:
                        print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record: {e}{Fore.RESET}')
                        report.append(f'{indent}Could not resolve the SPF Record: {e}\n')

                    subnetsTmp = []
                    for txt in txtRecords:
                        for subnet in txt:
                            subnetsTmp.append(re.findall(r'ip4:(.*)', subnet))

                    if any('ip4:' in subnetss for sublist in subnetsTmp for subnetss in sublist):
                        subnets = []
                        for subnet in subnetsTmp:
                            for x in subnet:
                                substrings = x.split(' ')
                                subnets.extend(s for s in substrings if s.startswith('ip4:'))

                        ipSubnets = []
                        for subnet in subnets:
                            subnet = subnet.replace('ip4:', '')
                            networks = subnet.split(' ')
                            for network in networks:
                                if '/' in network:
                                    ipSubnets.append(ipaddress.ip_network(network, strict=False))

                        if any(ipaddress.ip_address(authResultOrigIP[0]) in subnet for subnet in ipSubnets):
                            print(f'{Fore.LIGHTGREEN_EX}{indent}→ No Mismatch detected.{Fore.RESET}')
                            report.append(f'\n{indent}→ No Mismatch detected.')
                        else:
                            print(f'{Fore.LIGHTRED_EX}{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({" ".join([" ".join(t) for t in txtRecords])}){Fore.RESET}')
                            report.append(f'\n{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({" ".join([" ".join(t) for t in txtRecords])})')

                    elif not any(subnet for subnet in subnetsTmp):
                        includeTmp = []
                        for txt in txtRecords:
                            for include in txt:
                                includeTmp.append(re.findall(r'include:(.*)', include))
                        
                        includeTmp = [x for x in includeTmp if x]
                        extractionIncludeValue = [x for sublist in includeTmp for x in sublist]
                        extractionIncludeValue = [mechanism for string in extractionIncludeValue for mechanism in string.split()]
                        extractionIncludeValue = [mechanism for mechanism in extractionIncludeValue if mechanism not in ["~all", "-all"]]

                        txtRecordsOfInclude = []
                        for include in extractionIncludeValue:
                            try:
                                spfResultsInclude = dns.resolver.resolve(include, 'TXT')
                                for spfInclude in spfResultsInclude:
                                    spfResultsInclude = spfInclude.to_text().lower()
                                    txtRecordsOfInclude.append(re.findall(r'"(.*?)"', spfResultsInclude))
                            except dns.resolver.LifetimeTimeout as e:
                                print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record: {e}{Fore.RESET}') 
                                report.append(f'Could not resolve the SPF Record: {e}\n')
                        
                        extractionSecondLevel = [y for subsublist in txtRecordsOfInclude for y in subsublist]
                        extractionSecondLevel = [technique for idontknow in extractionSecondLevel for technique in idontknow.split()]
                        extractionSecondLevel = [technique for technique in extractionSecondLevel if technique not in['~all', '-all']]
                        extractionSecondLevel = [technique for technique in extractionSecondLevel if technique != 'v=spf1']
                        includeDomains = [mechanism.split(':')[1] for mechanism in extractionSecondLevel if mechanism.startswith('include:')]

                        txtRecordOfIncludeSecond = [] 
                        for domain in includeDomains:
                            try: 
                                resultsOfInclude = dns.resolver.resolve(domain, 'TXT')
                                for p in resultsOfInclude:
                                    includeResults = p.to_text().lower()
                                    txtRecordOfIncludeSecond.append(re.findall(r'"(.*?)"', includeResults))
                            except dns.resolver.LifetimeTimeout as e:
                                print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record: {e}{Fore.RESET}')  
                                report.append(f'Could not resolve the SPF Record: {e}\n')

                        subnetsOfInclude = []
                        for b in txtRecordOfIncludeSecond:
                            for h in b:
                                subnetsOfInclude.append(re.findall(r'ip4:(.*)', h))
                        
                        if any('ip4:' in subnet for sublist in subnetsOfInclude for subnet in sublist):
                            print(f'{Fore.LIGHTYELLOW_EX}{indent}{indent}Getting deeper into the SPF Records...{Fore.RESET}')
                            report.append(f'\n{indent}{indent}Getting deeper into the SPF Records...')
                            subnets = []
                            for subnet in subnetsOfInclude:
                                for x in subnet:
                                    substrings = x.split(' ')
                                    subnets.extend(s for s in substrings if s.startswith('ip4:'))

                            ipSubnets = []
                            for subnet in subnets:
                                subnet = subnet.replace('ip4:', '')
                                networks = subnet.split(' ')
                                for network in networks:
                                    if '/' in network:
                                        ipSubnets.append(ipaddress.ip_network(network, strict=False))

                            if any(ipaddress.ip_address(authResultOrigIP[0]) in subnet for subnet in ipSubnets):
                                print(f'{Fore.LIGHTGREEN_EX}{indent}{indent}→ No Mismatch detected.{Fore.RESET}')
                                report.append(f'\n{indent}{indent}→ No Mismatch detected.')
                            else:
                                print(f'{Fore.LIGHTRED_EX}{indent}{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets}){Fore.RESET}')
                                report.append(f'\n{indent}{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets})')
                    else:
                        print(f'{Fore.LIGHTRED_EX}{indent}{indent}→ Could not detect SPF Record. Manual Reviewing required.{Fore.RESET}')
                        report.append(f'{indent}{indent}→ Could not detect SPF Record. Manual Reviewing required.')
        else:
            print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            report.append(f'Could not detect SMTP Server. Manual reviewing required.\n')

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for Field Mismatches...{Fore.RESET}')
    report.append('\nChecking for Field Mismatches...\n')

    if content['message-id'] is not None:
        print(f'{Fore.LIGHTGREEN_EX}Message-ID Field detected !{Fore.RESET}')
        report.append('Message-ID Field detected !\n')
        messageIDDomain = content['message-id'].split('@')[1].split('>')[0]
        if fromEmailDomain != messageIDDomain:
            print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: Message-ID Domain "{messageIDDomain}" NOT EQUAL "FROM" Domain "{fromEmailDomain}"{Fore.RESET}')
            report.append(f'{indent}→ Suspicious activity detected: Message-ID Domain ({messageIDDomain}) NOT EQUAL "FROM" Domain ({fromEmailDomain})\n')
        else:
            print(f'{Fore.LIGHTGREEN_EX}{indent}→ No Mismatch detected.{Fore.RESET}')
            report.append(f'{indent}→ No Mismatch detected.\n') 
    else:
        print(f'{Fore.WHITE}No Message-ID Field detected. Skipping...{Fore.RESET}')
        report.append('No Message-ID Field detected. Skipping...\n')

    if fromMatch.group(1) is not None and content['reply-to'] is not None:
        print(f'{Fore.LIGHTGREEN_EX}Reply-To Field detected !{Fore.RESET}')
        report.append('Reply-To Field detected !')
        
        if formatReplyTo == False:
            if content['from'] != content['reply-to']:
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                report.append(f'{indent}→ No "FROM - REPLY-TO" Mismatch detected.')

        elif formatReplyTo == True:
            if fromMatch.group(1) != replyTo.group(1):
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                report.append(f'{indent}→ No "FROM - REPLY-TO" Mismatch detected.')
    else:
        print(f'{Fore.WHITE}No Reply-To Field detected. Skipping...{Fore.RESET}')
        report.append('No Reply-To Field detected. Skipping...\n')

    if fromMatch.group(1) is not None and content['return-path'] is not None:
        print(f'{Fore.LIGHTGREEN_EX}Return-Path Field detected !{Fore.RESET}')
        report.append('\nReturn-Path Field detected !')
      
        if formatReturnPath == False:
            if fromMatch.group(1) != content['return-path']:
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - RETURN-PATH" Mismatch detected.{Fore.RESET}')
                report.append(f'\n{indent}→ No "FROM - RETURN-PATH" Mismatch detected.')
        elif formatReturnPath == True:
            if fromMatch.group(1) != returnToPath.group(1):
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - RETURN-PATH" Mismatch detected.{Fore.RESET}')
                report.append(f'\n{indent}→ No "FROM - RETURN-PATH" Mismatch detected.')
    else:
        print(f'{Fore.WHITE}No Return-Path Field detected. Skipping...{Fore.RESET}')
        report.append('No Return-Path Field detected. Skipping...')
       
    print(f'\n{Fore.LIGHTYELLOW_EX}Note: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}')

    print(f'{Fore.LIGHTMAGENTA_EX}Checking with VirusTotal...{Fore.RESET}')
    report.append('\n\nChecking with VirusTotal...\n')

    if filteredIpv4:
        for ip in filteredIpv4:
            print(f'Detections: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/detection{Fore.RESET}')
            print(f'Relations: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/relations{Fore.RESET}')
            print(f'Graph: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/graph{Fore.RESET}')
            print(f'Network Traffic: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/network-traffic{Fore.RESET}')
            print(f'WHOIS: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/whois{Fore.RESET}')
            print(f'Comments: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/comments{Fore.RESET}')
            print(f'Votes: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/votes{Fore.RESET}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{ip}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{ip}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{ip}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{ip}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{ip}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{ip}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{ip}/votes\n')

    elif authResultOrigIP:
        for ip in authResultOrigIP:
            print(f'Detections: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/detection{Fore.RESET}')
            print(f'Relations: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/relations{Fore.RESET}')
            print(f'Graph: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/graph{Fore.RESET}')
            print(f'Network Traffic: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/network-traffic{Fore.RESET}')
            print(f'WHOIS: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/whois{Fore.RESET}')
            print(f'Comments: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/comments{Fore.RESET}')
            print(f'Votes: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ip}/votes{Fore.RESET}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{ip}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{ip}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{ip}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{ip}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{ip}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{ip}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{ip}/votes\n')
    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
        report.append(f'Could not detect SMTP Server. Manual reviewing required.')

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with AbuseIPDB...{Fore.RESET}')
    report.append('\nChecking with AbuseIPDB...\n')

    if filteredIpv4:
        for ip in filteredIpv4:
            print(f'AbuseIPDB: {Fore.LIGHTGREEN_EX}https://www.abuseipdb.com/check/{ip}{Fore.RESET}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{ip}\n')
        
    elif authResultOrigIP:
        for ip in authResultOrigIP:
            print(f'AbuseIPDB: {Fore.LIGHTGREEN_EX}https://www.abuseipdb.com/check/{ip}{Fore.RESET}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{ip}\n')
    
    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
        report.append(f'Could not detect SMTP Server. Manual reviewing required.')

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with IPQualityScore...{Fore.RESET}')
    report.append('\n\nChecking with IPQualityScore...\n')

    if filteredIpv4:
        for ip in filteredIpv4:
            print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}{Fore.RESET}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}\n')

    elif authResultOrigIP:
        for ip in authResultOrigIP:
            print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}{Fore.RESET}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}\n')
    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
        report.append(f'Could not detect SMTP Server. Manual reviewing required.')
    
    return ''.join(report)


def check_attachment(attachment):
    result = []

    print(f'\n\n{Fore.LIGHTBLUE_EX}Checking the attachment...{Fore.RESET}')
    result.append('\n\nChecking the attachment...\n')
    
    sha256 = hashlib.sha256()
    BUFFER = 65536
    
    with open(attachment, 'rb') as file:
        while True:
            data = file.read(BUFFER)
            if not data:
                break
            sha256.update(data)

    print(f'{indent}--> Link: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/file/{sha256.hexdigest()}/detection{Fore.RESET}')
    result.append(f'--> Link: https://www.virustotal.com/gui/file/{sha256.hexdigest()}/detection')

    return '\n'.join(result)

def checkForUpdates(): 
    try:
        response = requests.get('https://api.github.com/repos/B0lg0r0v/Elyzer/releases/latest')
    except requests.exceptions.ConnectionError:
        print(f'{Fore.RED}No internet connection.{Fore.RESET}')
        exit()    
    
    latestRelease = json.loads(response.text)
    if 'tag_name' in latestRelease:
        latestVersion = latestRelease['tag_name'].lower()
        match = re.search(r'v\d+\.\d\.\d+', latestVersion)
        if match:
            latestVersion = match.group(0)
        if CURRENT_VERSION != latestVersion:
            if latestVersion > CURRENT_VERSION:
                print(f'A new version ({latestVersion}) is available. Please download it from the release section on GitHub.{Fore.RESET}\n')
            elif latestVersion == CURRENT_VERSION:
                pass
            elif latestVersion < CURRENT_VERSION:
                pass 

def generate_json_report(file, attachment=None):
    report = {
        "general_information": generalInformation(file),
        "routing": routing(file),
        "security_information": securityInformations(file),
        "envelope": envelope(file),
        "spoofing_check": spoofing(file)
    }

    if attachment:
        report["attachment_check"] = check_attachment(attachment)

    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    with open(f'elyzer_report_{timestamp}.json', 'w', encoding='UTF-8') as json_file:
        json.dump(report, json_file, indent=4)

    print(f'\n\n\n{Fore.GREEN}-----> JSON Report saved as "elyzer_report_{timestamp}.json"{Fore.RESET}')


if __name__ == '__main__':
    print(r"""
   ____ ____  __ ____   ____ ___ 
  / __// /\ \/ //_  /  / __// _ \
 / _/ / /__\  /  / /_ / _/ / , _/
/___//____//_/  /___//___//_/|_| v0.3.4
                                  
    Author: B0lg0r0v
    https://arthurminasyan.com
    """)
    print("\n")

    colorama_init()
    indent = ' ' * 3
    CURRENT_VERSION = 'v0.3.4'
    savings = []

    checkForUpdates()

    parser = ArgumentParser()
    parser.add_argument('-f', '--file', help='Give the E-Mail Header as a file.', required=True)
    parser.add_argument('-v', '--version', action='version', version=f'Elyzer {CURRENT_VERSION}')
    parser.add_argument('-a', '--attachment', help='Check if the file is malicious.')
    parser.add_argument('-j', '--json', help='Generate report in JSON format', action='store_true')
    parser.add_argument('--passive', help='Enable passive mode to skip DNS resolution', action='store_true')
    args = parser.parse_args()

    if args.file is not None:  
        print(f'{Fore.YELLOW}E-Mail Header Analysis complete{Fore.RESET}')

        if args.attachment:
            with open(f'elyzer_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt', 'w', encoding='UTF-8') as report:
                report.write(f'Elyzer {CURRENT_VERSION}\n' + 'Author: B0lg0r0v\n' + 'https://arthurminasyan.com\n\n' +  generalInformation(args.file) + 
                            '\n' + routing(args.file) + '\n' + securityInformations(args.file) + 
                            '\n' + envelope(args.file) + '\n' + spoofing(args.file, args.passive) + '\n' + check_attachment(args.attachment)) 
        else:
            with open(f'elyzer_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt', 'w', encoding='UTF-8') as report:
                report.write(f'Elyzer {CURRENT_VERSION}\n' + 'Author: B0lg0r0v\n' + 'https://arthurminasyan.com\n\n' +  generalInformation(args.file) + 
                            '\n' + routing(args.file) + '\n' + securityInformations(args.file) + 
                            '\n' + envelope(args.file) + '\n' + spoofing(args.file, args.passive))

        if args.json:
            generate_json_report(args.file, args.attachment)

        print(f'\n\n\n{Fore.GREEN}-----> Report saved as "elyzer_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt"{Fore.RESET}')
    else:
        parser.error('E-Mail Header is required.')

