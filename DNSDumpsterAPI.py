"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains

"""

from __future__ import print_function
import requests
import re
import sys
import base64

from bs4 import BeautifulSoup


class DNSDumpsterAPI(object):

    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False, session=None):
        self.verbose = verbose
        if not session:
            self.session = requests.Session()
        else:
            self.session = session

    def display_message(self, s):
        if self.verbose:
            print('[verbose] %s' % s)

    def retrieve_results(self, table):
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip = re.findall(pattern_ip, tds[1].text)[0]
                domain = str(tds[0]).split('<br/>')[0].split('>')[1].split('<')[0]
                header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
                reverse_dns = tds[1].find('span', attrs={}).text

                additional_info = tds[2].text
                country = tds[2].find('span', attrs={}).text
                autonomous_system = additional_info.split(' ')[0]
                provider = ' '.join(additional_info.split(' ')[1:])
                provider = provider.replace(country, '')
                data = {'domain': domain,
                        'ip': ip,
                        'reverse_dns': reverse_dns,
                        'as': autonomous_system,
                        'provider': provider,
                        'country': country,
                        'header': header}
                res.append(data)
            except:
                pass
        return res

    def retrieve_txt_record(self, table):
        res = []
        for td in table.findAll('td'):
            res.append(td.text)
        return res


    def search(self, domain):
        dnsdumpster_url = 'https://dnsdumpster.com/'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

        try:
            req = self.session.get(dnsdumpster_url, headers=headers, timeout=10)
        except Exception as e:
            print("Could not connect to dnsdumpster.com: %s" % str(e), file=sys.stderr)
            return {'domain': domain, 'dns_records': {'dns': [], 'mx': [], 'txt': [], 'host': []}, 'image_data': None, 'xls_data': None}

        soup = BeautifulSoup(req.content, 'html.parser')

        # Try multiple methods to find CSRF token
        csrf_middleware = None
        csrf_input = soup.find('input', attrs={'name': 'csrfmiddlewaretoken'})
        if csrf_input:
            csrf_middleware = csrf_input.get('value')
        else:
            # Try extracting from cookies
            csrf_middleware = req.cookies.get('csrftoken')
        if not csrf_middleware:
            # Try regex fallback
            match = re.search(r'csrfmiddlewaretoken["\'\s]+value=["\']([^"\']+)', req.content.decode('utf-8', errors='ignore'))
            if match:
                csrf_middleware = match.group(1)

        if not csrf_middleware:
            print("Warning: Could not retrieve CSRF token from dnsdumpster.com (site may have changed)", file=sys.stderr)
            return {'domain': domain, 'dns_records': {'dns': [], 'mx': [], 'txt': [], 'host': []}, 'image_data': None, 'xls_data': None}

        self.display_message('Retrieved token: %s' % csrf_middleware)

        cookies = {'csrftoken': csrf_middleware}
        headers['Referer'] = dnsdumpster_url
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain, 'user': 'free'}

        try:
            req = self.session.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers, timeout=15)
        except Exception as e:
            print("Could not post to dnsdumpster.com: %s" % str(e), file=sys.stderr)
            return {'domain': domain, 'dns_records': {'dns': [], 'mx': [], 'txt': [], 'host': []}, 'image_data': None, 'xls_data': None}

        if req.status_code != 200:
            print(
                "Unexpected status code from {url}: {code}".format(
                    url=dnsdumpster_url, code=req.status_code),
                file=sys.stderr,
            )
            return {'domain': domain, 'dns_records': {'dns': [], 'mx': [], 'txt': [], 'host': []}, 'image_data': None, 'xls_data': None}

        if 'There was an error getting results' in req.content.decode('utf-8', errors='ignore'):
            print("There was an error getting results", file=sys.stderr)
            return {'domain': domain, 'dns_records': {'dns': [], 'mx': [], 'txt': [], 'host': []}, 'image_data': None, 'xls_data': None}

        soup = BeautifulSoup(req.content, 'html.parser')
        tables = soup.findAll('table')

        res = {}
        res['domain'] = domain
        res['dns_records'] = {}
        res['dns_records']['dns'] = self.retrieve_results(tables[0]) if len(tables) > 0 else []
        res['dns_records']['mx'] = self.retrieve_results(tables[1]) if len(tables) > 1 else []
        res['dns_records']['txt'] = self.retrieve_txt_record(tables[2]) if len(tables) > 2 else []
        res['dns_records']['host'] = self.retrieve_results(tables[3]) if len(tables) > 3 else []

        # Network mapping image
        try:
            tmp_url = 'https://dnsdumpster.com/static/map/{}.png'.format(domain)
            image_data = base64.b64encode(self.session.get(tmp_url).content)
        except:
            image_data = None
        finally:
            res['image_data'] = image_data

        # XLS hosts.
        try:
            pattern = r'/static/xls/' + domain + '-[0-9]{12}\.xlsx'
            xls_url = re.findall(pattern, req.content.decode('utf-8', errors='ignore'))[0]
            xls_url = 'https://dnsdumpster.com' + xls_url
            xls_data = base64.b64encode(self.session.get(xls_url).content)
        except Exception as err:
            xls_data = None
        finally:
            res['xls_data'] = xls_data

        return res
