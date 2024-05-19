from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import csv
import requests
import pandas as pd
import json
from datetime import datetime
from urllib.parse import urlparse

class Phisherman:
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.success = 0
        self.driver = None
        self.filename = f"file/phishing_tank_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"


    def __enter__(self):
        self.driver = webdriver.Firefox()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.driver:
            self.driver.quit()

    def make_page_url(self, page):
        return f"https://www.phishtank.com/phish_search.php?page={page}&active=y&valid=y&Search=Search"

    def make_detail_page_url(self, url_id):
        return f"https://www.phishtank.com/phish_detail.php?phish_id={url_id}"

    def get_ids(self, page):
        print(f"Gathering links from page [{page}]... ", end="")
        self.driver.get(self.make_page_url(page))
        try:
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".value:first-child > a")))
            elements = self.driver.find_elements(By.CSS_SELECTOR, ".value:first-child > a")
            url_ids = [element.text for element in elements]
            print("Success")
            return url_ids
        except Exception as e:
            print(f"Error: {e}")
            return []

    def get_data(self, url_id):
        print(f"Gathering data for url [id={url_id}]... ", end="")
        
        self.driver.get(self.make_detail_page_url(url_id))
        
        try:
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".padded > div:nth-child(4) > span:nth-child(1) > b:nth-child(1)")))
            phish_url = self.driver.find_element(By.CSS_SELECTOR, ".padded > div:nth-child(4) > span:nth-child(1) > b:nth-child(1)").text
            self.success += 1
            
            with open(self.filename, 'a', newline='') as csvfile:
                
                writer = csv.writer(csvfile)
                writer.writerow([phish_url])
        except Exception as e:
            print(f"Error: {e}")
            
    def get_commom_crawl_url(self, crawler_code, url_pattern):
        return f"https://index.commoncrawl.org/{crawler_code}-index?url={url_pattern}&output=json"
    
    def get_crawler_codes(self):
        self.driver.get(f"https://index.commoncrawl.org/")
        try:
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, "#searchForm #ccIndices option")))
            options = self.driver.find_elements(By.CSS_SELECTOR, "#searchForm #ccIndices option")
            crawler_codes = [option.get_attribute("value") for option in options]
            return crawler_codes
        except Exception as e:
            print(f"Error: {e}")

    def send_get_request(self, url):
        try:
            response = requests.get(url)
            print(response)
            response.raise_for_status()  # Check for HTTP errors
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            return None
    

    def get_data_from_common_crawl(self, start, end, pattern, crawler_code):
    # Send the get request to retrieve response data
        response_data = self.send_get_request(self.get_commom_crawl_url(crawler_code, pattern))
        
        if response_data:
            # Preprocess the response data to form a valid JSON array
            response = response_data.replace('\n', '')
            response = response.replace('}{', '},{')
            response = "[" + response + "]"
            json_data = json.loads(response)
            
            # Ensure start and end are within the bounds of json_data
            start = int(start)  # Ensure start is not negative
            end = min(int(end), len(json_data))  # Ensure end is not beyond the length of json_data
            # Define the field names for the CSV
            fieldnames = ["url"]
            
            # Generate the dynamic filename
            current_datetime = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'file/legitimate_commoncrawl_{current_datetime}.csv'
            print("start:")
            print(start)
            print("end:")
            print(end)
            
            def get_domain(url):
                return urlparse(url).netloc
            
            # Open the file with the dynamic filename for writing
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write the header row
                writer.writeheader()
                
                seen_domains = set()
                # Iterate over the specified range within json_data
                for row in json_data[start:end]:
                    url = row.get("url", '')
                    domain = get_domain(url)
                    
                    # Skip duplicate domains
                    if domain in seen_domains:
                        continue
                    
                    seen_domains.add(domain)
                    filtered_row = {"url": url}
                    writer.writerow(filtered_row)
            
            # Return the filename of the written CSV file
            return filename

            # Convert to DataFrame and save to CSV
            # df = pd.DataFrame(json_data)
            # csv_file = 'output.csv'
            # df.to_csv(csv_file, index=False)
 

        # print("String has been written to output.txt")
            # else:
            #     print("No data received from the Common Crawl request.")
        
        # except Exception as e:
        #     print(f"Error: {e}")
            


    def find_last_crawled_url_page(self, last_crawled_id): 
        for page in range(1, 100):
            result = self.get_ids(page)
            if result:
                for url_id in result:
                    if last_crawled_id == url_id:
                        return page
        return 1  # Return 1 if not found, so it starts from the beginning

    def crawl(self, last_crawler_url_id):
        last_page = self.find_last_crawled_url_page(last_crawler_url_id)
        print("Start crawling! Phisherman is gathering data... from page:  ")
        print(last_page)
        last_id = last_crawler_url_id
        if (int(last_page) == 1):
            print("No more newer url to crawl")
            return last_id
        flag = 0
        
        for page in range(self.start, int(last_page) - 1):
            result = self.get_ids(page)
            if result:
                for url_id in result:
                    self.get_data(url_id)
                    if flag == 0:
                        last_id = url_id
                        flag = 1
        print(f"Crawling complete! Successfully gathered {self.success} URLs")
        return last_id
