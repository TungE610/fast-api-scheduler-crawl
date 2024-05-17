from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi_amis_admin.admin.settings import Settings
from fastapi_amis_admin import i18n
from fastapi_amis_admin import amis
from fastapi_amis_admin.admin import admin
i18n.set_language(language='en_US')
from fastapi_amis_admin.admin.site import AdminSite
from fastapi_amis_admin.amis.components import PageSchema, Page
from datetime import date
from file_admin import CrawledFileAdmin
from fastapi_scheduler import SchedulerAdmin
from crawler import Phisherman
from fastapi_amis_admin.amis.components import Page, PageSchema, Property
import csv
import whois
from datetime import datetime
from fastapi_config import ConfigModelAdmin, DbConfigStore, ConfigAdmin
from pydantic import BaseModel
from typing import List
from fastapi_amis_admin.models import Field
from sqlmodel import SQLModel
import pandas as pd
from extract_features import legitimateFeatureExtraction, phishingFeatureExtraction

# Create `FastAPI` application
# app.mount("/static", StaticFiles(directory="static"), name="static")

app = FastAPI()
# Create `AdminSite` instance
site = AdminSite(settings=Settings(debug=True, database_url_async='sqlite+aiosqlite:///amisadmin.db'))

dbconfig = DbConfigStore(site.db)

site.register_admin(ConfigModelAdmin)

# Create an instance of the scheduled task scheduler `SchedulerAdmin`

class ContactCfg(BaseModel):
    name: str = Field("", title="Name")
    qq: List[str] = Field("", title="QQ")


class SiteCfg(BaseModel):
    name: str = Field(..., title="Site Name")
    logo: str = Field("", title="Site LOGO", amis_form_item=amis.InputImage())
    contacts: List[ContactCfg] = Field([], title="Contact list")
    domains: List[str] = Field([], title='Domain list')


class SiteCfgAdmin(ConfigAdmin):
    page_schema = amis.PageSchema(label='Site Config')
    schema = SiteCfg

scheduler = SchedulerAdmin.bind(site)

last_crawler_url_id = "8576634"

# Add scheduled tasks, refer to the official documentation: https://apscheduler.readthedocs.io/en/master/
# use when you want to run the job at fixed intervals of time
@scheduler.scheduled_job('interval', seconds=86400, max_instances=1)
def crawl_phishing_url_from_phishing_tank():
    global last_crawler_url_id
    start, end = 1, 1

    with Phisherman(start, end) as phisherman:
        last_crawler_url_id = phisherman.crawl(last_crawler_url_id)
        print("last crawled index: ")
        print(last_crawler_url_id)

def feature_extraction(filename, label):
    phishing_url = pd.read_csv(filename)
    phish_features = []

    # Extract features for each URL in the range specified
    for i in range(0, len(phishing_url) - 1):
        url = phishing_url['url'][i]
        print(i)
        
        if (label == 0):
            phish_features.append(legitimateFeatureExtraction(url, label))
        else:
            phish_features.append(phishingFeatureExtraction(url, label))
    # Define the feature names
    feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
                    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                    'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards', 'Label']

    # Create a DataFrame with the extracted features
    phishing_df = pd.DataFrame(phish_features, columns=feature_names)

    # Save the DataFrame to a new CSV file
    output_csv_path = filename  # replace with your desired file path
    phishing_df.to_csv(output_csv_path, mode='w', header=True, index=False)

    print("Feature extraction and CSV creation completed successfully.")

@scheduler.scheduled_job('interval', seconds=30, max_instances=1)
async def crawl_legitimate_url_from_common_crawl():
    with Phisherman(1, 1) as phisherman:
        number =  await dbconfig.read('number')
        pattern =  await dbconfig.read('pattern')
        crawler_code =  await dbconfig.read('crawler_code')
                
        filename = phisherman.get_data_from_common_crawl(number.data, pattern.data, crawler_code.data)
        feature_extraction(filename, 0)
    

# use when you want to run the job periodically at certain time(s) of day
@scheduler.scheduled_job('cron', hour=3, minute=30)
def cron_task_test():
    print('cron task is run...')

# use when you want to run the job just once at a certain point of time
@scheduler.scheduled_job('date', run_date=date(2022, 11, 11))
def date_task_test():
    print('date task is run...')
class DataAdmin(admin.PageAdmin):
    page_schema = PageSchema(label="Data", icon="fa fa-database", url="/home", isDefaultPage=True, sort=100)
    page_path = "data"
    
    def get_legitimate_data(self):
        data = []
        with open('data/legitimate_data.csv', mode='r') as file:
        # Create a CSV reader object
            csv_reader = csv.reader(file)

        # Iterate over each row in the CSV file
            for row in csv_reader:
                # Append each row to the data list
                data.append(row) 
        return data
    
    def get_phishing_data(self):
        data = []
        with open('data/phishing_data.csv', mode='r') as file:
        # Create a CSV reader object
            csv_reader = csv.reader(file)

        # Iterate over each row in the CSV file
            for row in csv_reader:
                # Append each row to the data list
                data.append(row) 
        return data
    
    async def get_page(self, request: Request) -> Page:
        page = await super().get_page(request)
        legitimate_data = self.get_legitimate_data()
        phishing_data = self.get_phishing_data()
    
        page.body = [
            amis.Flex(items=[
                f"Legitimate data total rows: {len(legitimate_data)}",],justify="space-between", alignItems="center"),
            Property(
                title="Legitimate data",
                column=2,
                items=[
                    Property.Item(label="id", content=len(legitimate_data) - 1),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) - 1][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 2),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) - 2][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 3),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -3][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 4),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -4][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 5),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -5][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 6),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -6][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 7),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -7][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 8),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -8][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 9),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -9][1]),
                    Property.Item(label="id", content=len(legitimate_data) - 10),
                    Property.Item(label="Url", content=legitimate_data[len(legitimate_data) -10][1]),
                ],
            ),
            amis.Divider(),
            amis.Flex(items=[f"Phishing data total rows: {len(phishing_data)}"],justify="space-between", alignItems="center"),
            Property(
                title="Phishing data",
                column=2,
                items=[
                    Property.Item(label="id", content=len(phishing_data) - 1),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) - 1][1]),
                    Property.Item(label="id", content=len(phishing_data) - 2),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) - 2][1]),
                    Property.Item(label="id", content=len(phishing_data) - 3),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -3][1]),
                    Property.Item(label="id", content=len(phishing_data) - 4),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -4][1]),
                    Property.Item(label="id", content=len(phishing_data) - 5),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -5][1]),
                    Property.Item(label="id", content=len(phishing_data) - 6),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -6][1]),
                    Property.Item(label="id", content=len(phishing_data) - 7),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -7][1]),
                    Property.Item(label="id", content=len(phishing_data) - 8),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -8][1]),
                    Property.Item(label="id", content=len(phishing_data) - 9),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -9][1]),
                    Property.Item(label="id", content=len(phishing_data) - 10),
                    Property.Item(label="Url", content=phishing_data[len(phishing_data) -10][1]),
                ],
            ),
        ]
        return page
# class FileAdmin(admin.PageAdmin):
#     page_schema = PageSchema(label="Crawled File", icon="fa fa-file", url="/files", isDefaultPage=True, sort=100)
#     page_path = "files"
    
#     async def get_page(self, request: Request) -> Page:
#         page = await super().get_page(request)
        
#         page.body = []
#         return page
class DataVisualAdmin(admin.PageAdmin):
    page_schema = PageSchema(label="Data visualization", icon="fa fa-pie-chart", url="/data-visualization", isDefaultPage=True, sort=100)
    page_path = "data-visualization"
    async def get_page(self, request: Request) -> Page:
        page = await super().get_page(request)
        
        page.body = [
            amis.Grid(
                columns=[amis.Grid.Column(
                    body=[
                        amis.Card.Media(
                            url="plot/images.png"
                        ),
                        amis.Card.Media(
                            url="plot/images.png"
                        ),
                    ]    
                ),
                amis.Grid.Column(
                    body=[
                        amis.Card.Media(
                            url="plot/images.png"
                        ),
                        amis.Card.Media(
                            url="plot/images.png"
                        ),
                    ]    
                )
                ]
            )
        ]
        return page
site.register_admin(DataAdmin, CrawledFileAdmin, DataVisualAdmin)

site.mount_app(app)


@app.on_event("startup")
async def startup():
    # Mount the background management system
    # Start the scheduled task scheduler
    scheduler.start()    
    await site.db.async_run_sync(SQLModel.metadata.create_all, is_session=False)



if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, debug=True)
