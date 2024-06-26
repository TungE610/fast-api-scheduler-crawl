# 1.Domain of the URL (Domain) 
import pandas as pd
import pytz  # You'll need this if dealing with timezone-aware datetime objects

from urllib.parse import urlparse,urlencode
import ipaddress
import re
import re
from bs4 import BeautifulSoup
import whois
import urllib.request
from datetime import datetime
import requests

def getDomain(url):  
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    if not domain:
        domain = url
    return domain

# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
    if "@" in url:
        at = 1    
    else:
        at = 0    
    return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    if len(url) < 54:
        length = 0            
    else:
        length = 1            
    return length

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth+1
    return depth

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0
    
# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0
    
#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0
    
# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate
    
# 12.Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        if url.startswith("http:/") or url.startswith("https:/"):
            url = url[len("http:/"):]

        # Encode the URL to handle special characters
        encoded_url = requests.utils.quote(url, safe='')
        
        # Fetch the webpage content
        response = requests.get(f"https://www.semrush.com/analytics/overview/?q={encoded_url}&searchType=domain")
        response.raise_for_status()  # Raise an exception for bad status codes
        
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find the <a> tag with aria-label containing the domain rank
        domain_rank_tag = soup.find('a', {'aria-label': lambda x: x and x.startswith('Domain Rank is')})
        if domain_rank_tag:
            rank_text = domain_rank_tag['aria-label']
            rank_start_index = rank_text.find('is') + len('is')
            rank_end_index = rank_text.find(',', rank_start_index)
            rank_str = rank_text[rank_start_index:rank_end_index].replace(',', '').strip()
            rank = int(rank_str) if rank_str.isdigit() else None
            if rank is not None and rank > 10000000:
                return 1  # low traffic
    except Exception as e:
        print(f"Error: {e}")
    
    return 0

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    
    # Function to ensure the datetime objects are timezone-naive
    def make_naive(dt):
        if dt.tzinfo is not None:
            return dt.astimezone(pytz.utc).replace(tzinfo=None)
        return dt

    # Check if dates are in string format and convert them
    if isinstance(creation_date, str) or isinstance(expiration_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except Exception as e:
            return 1
    
    # If either date is None, return 1
    if creation_date is None or expiration_date is None:
        return 1
    
    # Handle the case where dates are lists (take the first element if they are lists)
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    
    # Make both dates naive
    creation_date = make_naive(creation_date)
    expiration_date = make_naive(expiration_date)
    
    # Calculate the age of the domain
    ageofdomain = abs((expiration_date - creation_date).days)
    if (ageofdomain / 30) < 6:
        age = 1
    else:
        age = 0
    
    return age

# 14.End time of domain: The difference between termination time and current time (Domain_End) 
def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    
    # Define today's date in UTC
    today = datetime.now(pytz.utc)
    
    # Helper function to ensure datetime is naive (no timezone info)
    def make_naive(dt):
        if dt.tzinfo is not None:
            return dt.astimezone(pytz.utc).replace(tzinfo=None)
        return dt

    # If expiration_date is a string, convert it to datetime
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            expiration_date = make_naive(expiration_date)
        except:
            return 1
    
    # If expiration_date is None, return 1
    if expiration_date is None:
        return 1
    
    # If expiration_date is a list, take the first element
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    
    # Ensure expiration_date is naive
    expiration_date = make_naive(expiration_date)
    
    # Calculate the difference in days
    end = abs((expiration_date - today.replace(tzinfo=None)).days)
    
    # Determine the domain end status
    if (end / 30) < 6:
        return 1
    else:
        return 0

# 15. IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1
      
# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0
    
# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1
    
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1
    
def legitimateFeatureExtraction(url,label):

  features = []
  #Address bar based features (10)
  features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))

  dns = 0
  domain_name = None
  flags = 0
  flags = flags | whois.NICClient.WHOIS_QUICK
  try:
    domain_name = whois.whois(getDomain(url), flags=flags)
  except:
    dns = 1

  features.append(dns)
  features.append(0)
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  
  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  features.append(label)
  
  return features

def extractForInference(url):

  features = []
  #Address bar based features (10)
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))

  dns = 0
  domain_name = None
  flags = 0
  flags = flags | whois.NICClient.WHOIS_QUICK
  try:
    domain_name = whois.whois(getDomain(url), flags=flags)
  except:
    dns = 1

  features.append(dns)
  features.append(getLength(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  
  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  
  return features

def phishingFeatureExtraction(url,label):

  features = []
  #Address bar based features (10)
  features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))

  dns = 0
  try:
    domain_name = whois.whois(getDomain(url))
  except:
    dns = 1

  features.append(dns)
  features.append(1)
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  
  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  features.append(label)
  
  return features