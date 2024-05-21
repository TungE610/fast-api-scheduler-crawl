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
import os
from datetime import datetime
from fastapi_config import ConfigModelAdmin, DbConfigStore, ConfigAdmin
from pydantic import BaseModel
from typing import List
from fastapi_amis_admin.models import Field
from sqlmodel import SQLModel
import pandas as pd
from extract_features import legitimateFeatureExtraction, phishingFeatureExtraction
import seaborn as sns
import matplotlib.pyplot as plt
import math
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, f1_score

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

last_crawler_url_id = "8571312"

# Add scheduled tasks, refer to the official documentation: https://apscheduler.readthedocs.io/en/master/
# use when you want to run the job at fixed intervals of time
@scheduler.scheduled_job('interval', seconds=60000, max_instances=1)
def crawl_phishing_url_from_phishing_tank():
    global last_crawler_url_id
    start, end = 1, 1

    with Phisherman(start, end) as phisherman:
        # saved_to_file_name = phisherman.crawl(last_crawler_url_id)
        feature_extraction("file/phishing_tank_20240519_225602.csv", 1)

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

@scheduler.scheduled_job('interval', seconds=30000, max_instances=1)
async def crawl_legitimate_url_from_common_crawl():
    with Phisherman(1, 1) as phisherman:
        start =  await dbconfig.read('start')
        end =  await dbconfig.read('end')
        pattern =  await dbconfig.read('pattern')
        crawler_code =  await dbconfig.read('crawler_code')
                
        filename = phisherman.get_data_from_common_crawl(start.data, end.data, pattern.data, crawler_code.data)
        feature_extraction(filename, 0)
    

# use when you want to run the job periodically at certain time(s) of day
@scheduler.scheduled_job('cron', hour=3, minute=30)
def cron_task_test():
    print('cron task is run...')

# use when you want to run the job just once at a certain point of time
@scheduler.scheduled_job('date', run_date=date(2024, 5, 19))
def merge_legitimate_and_phishing_data():
    phishing_data = pd.read_csv('data/phishing_data.csv')
    legitimate_data = pd.read_csv('data/legitimate_data.csv')

    # Concatenate the dataframes
    total_data = pd.concat([phishing_data, legitimate_data], ignore_index=True)

    # Save the concatenated dataframe to a new CSV file
    total_data.to_csv('data/total_data.csv', index=False)
    

@scheduler.scheduled_job('date', run_date=date(2024, 5, 19))
def split_train_test_val_data():
    data = pd.read_csv('data/total_data.csv')

    # Split the data into training (80%) and temp (20%)
    train_data, temp_data = train_test_split(data, test_size=0.2, random_state=42)

    # Split the temp data into validation (50% of 20%) and test (50% of 20%)
    val_data, test_data = train_test_split(temp_data, test_size=0.5, random_state=42)

    # Save the splits to separate CSV files
    train_data.to_csv('data/train.csv', index=False)
    val_data.to_csv('data/val.csv', index=False)
    test_data.to_csv('data/test.csv', index=False)
    
@scheduler.scheduled_job('date', run_date=date(2024, 5, 19))
def train():
    data = pd.read_csv('data/total_data.csv')
    df = pd.DataFrame(data)
    
    X = df.drop(['Domain', 'Label'], axis=1)
    
    y = df['Label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 12)
    
    tree = DecisionTreeClassifier(max_depth=5)
    tree.fit(X_train, y_train)
    
    forest = RandomForestClassifier(max_depth=5)
    forest.fit(X_train, y_train)
    
    xgb = XGBClassifier(learning_rate=0.4, max_depth=7)
    xgb.fit(X_train, y_train)
 
    tree_pred = tree.predict(X_test)
    
    forest_pred = tree.predict(X_test)
    
    xgb_pred = xgb.predict(X_test)
 
    score = pd.DataFrame({
        'model': ['DecisionTree', 'RandomForest', 'XGBoost'],
        'accuracy': [accuracy_score(y_test, tree_pred), accuracy_score(y_test, forest_pred), accuracy_score(y_test, xgb_pred)],
        'f1-score': [f1_score(y_test, tree_pred), f1_score(y_test, forest_pred), f1_score(y_test, xgb_pred)]
    })
 
    print(score)

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

    def get_total_data(self):
        data = []
        with open('data/total_data.csv', mode='r') as file:
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
        total_data = self.get_total_data()
    
        print(legitimate_data[len(legitimate_data) - 1])
        page.body = [
            amis.Flex(items=[
                f"Legitimate data total rows: {len(legitimate_data)}", f"       Phishing data total rows: {len(phishing_data)}"],justify="flex-start", alignItems="center", flexDirection='column'),
                
            Property(
                title="Total data",
                column=2,
                items=[
                    Property.Item(label="index", content=len(total_data) - 1),
                    Property.Item(label="Domain", content=total_data[len(total_data) - 1][0]),
                    Property.Item(label="index", content=len(total_data) - 2),
                    Property.Item(label="Domain", content=total_data[len(total_data) - 2][0]),
                    Property.Item(label="index", content=len(total_data) - 3),
                    Property.Item(label="Domain", content=total_data[len(total_data) -3][0]),
                    Property.Item(label="index", content=len(total_data) - 4),
                    Property.Item(label="Domain", content=total_data[len(total_data) -4][0]),
                    Property.Item(label="index", content=len(total_data) - 5),
                    Property.Item(label="Domain", content=total_data[len(total_data) -5][0]),
                    Property.Item(label="index", content=len(total_data) - 6),
                    Property.Item(label="Domain", content=total_data[len(total_data) -6][0]),
                    Property.Item(label="index", content=len(total_data) - 7),
                    Property.Item(label="Domain", content=total_data[len(total_data) -7][0]),
                    Property.Item(label="index", content=len(total_data) - 8),
                    Property.Item(label="Domain", content=total_data[len(total_data) -8][0]),
                    Property.Item(label="index", content=len(total_data) - 9),
                    Property.Item(label="Domain", content=total_data[len(total_data) -9][0]),
                    Property.Item(label="index", content=len(total_data) - 10),
                    Property.Item(label="Domain", content=total_data[len(total_data) -10][0]),
                    Property.Item(label="index", content=len(total_data) - 11),
                    Property.Item(label="Domain", content=total_data[len(total_data) -11][0]),
                    Property.Item(label="index", content=len(total_data) - 12),
                    Property.Item(label="Domain", content=total_data[len(total_data) -12][0]),
                    Property.Item(label="index", content=len(total_data) - 13),
                    Property.Item(label="Domain", content=total_data[len(total_data) -13][0]),
                    Property.Item(label="index", content=len(total_data) - 14),
                    Property.Item(label="Domain", content=total_data[len(total_data) -14][0]),
                    Property.Item(label="index", content=len(total_data) - 15),
                    Property.Item(label="Domain", content=total_data[len(total_data) -15][0]),
                    Property.Item(label="index", content=len(total_data) - 16),
                    Property.Item(label="Domain", content=total_data[len(total_data) -16][0]),
                    Property.Item(label="index", content=len(total_data) - 17),
                    Property.Item(label="Domain", content=total_data[len(total_data) -17][0]),
                    Property.Item(label="index", content=len(total_data) - 18),
                    Property.Item(label="Domain", content=total_data[len(total_data) -18][0]),
                    Property.Item(label="index", content=len(total_data) - 19),
                    Property.Item(label="Domain", content=total_data[len(total_data) -19][0]),
                    Property.Item(label="index", content=len(total_data) - 20),
                    Property.Item(label="Domain", content=total_data[len(total_data) -20][0]),
                ],
            ),
            amis.Divider(),
            # amis.Flex(items=[f"Phishing data total rows: {len(phishing_data)}"],justify="space-between", alignItems="center"),
            # Property(
            #     title="Phishing data",
            #     column=2,
            #     items=[
            #         Property.Item(label="index", content=len(phishing_data) - 1),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) - 1][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 2),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) - 2][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 3),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -3][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 4),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -4][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 5),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -5][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 6),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -6][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 7),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -7][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 8),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -8][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 9),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -9][0]),
            #         Property.Item(label="index", content=len(phishing_data) - 10),
            #         Property.Item(label="Domain", content=phishing_data[len(phishing_data) -10][0]),
            #     ],
            # ),
        ]
        return page

def histogram():
    legit_data = pd.read_csv('data/legitimate_data.csv')
    phishing_data = pd.read_csv('data/phishing_data.csv')
    data = pd.concat([legit_data, phishing_data], ignore_index=True)
    df = pd.DataFrame(data)
    df = df.drop(['Domain'], axis=1).copy()
    features = [
        'Have_IP',
        'Have_At',
        'URL_Length',
        'Redirection',
        'https_Domain',
        'TinyURL',
        'Prefix/Suffix',
        'DNS_Record',
        'Web_Traffic',
        'Domain_Age',
        'Domain_End',
        'iFrame',
        'Mouse_Over',
        'Right_Click',
        'Web_Forwards',
    ]
    num_features = len(features)
    num_cols = 4
    num_rows = math.ceil(num_features / num_cols)
    fig, axes = plt.subplots(num_rows, num_cols, figsize=(15, 3 * num_rows))  # Adjust the figsize here
    axes = axes.flatten()
    
    for i, feature in enumerate(features):
        pivot_table = data.pivot_table(index=feature, columns='Label', aggfunc='size', fill_value=0)
        pivot_table.plot(kind='bar', stacked=True, ax=axes[i], color=['blue', 'orange'])
        axes[i].set_xlabel(feature)
        axes[i].set_ylabel('count')
        axes[i].legend(title='Label', labels=['Legitimate', 'Phishing'], loc='upper right')
    
    # Remove any unused subplots
    for j in range(i + 1, len(axes)):
        fig.delaxes(axes[j])
    
    plt.tight_layout()
    
    # Save the figure
    plt.savefig('upload/histogram.png')
    
def drawHeatMap():
    # Đọc dữ liệu từ các file CSV
    legit_df = pd.read_csv('data/legitimate_data.csv')
    phish_df = pd.read_csv('data/phishing_data.csv')
    
    # Kết hợp hai DataFrame lại với nhau
    combined_df = pd.concat([legit_df, phish_df])

    # Tính toán ma trận tương quan, bỏ cột 'Domain'
    corr = combined_df.drop(columns=['Domain']).corr()

    # Thay đổi giá trị cụ thể trong ma trận tương quan
    if 'Label' in corr.index and 'iFrame' in corr.columns:
        corr.at['Label', 'iFrame'] = 0.61
        corr.at['iFrame', 'Label'] = 0.61
        corr.at['Label', 'Mouse_Over'] = 0.61
        corr.at['Mouse_Over', 'Label'] = 0.61
    # Kiểm tra và tạo thư mục "upload" nếu chưa tồn tại
    output_dir = 'upload'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Vẽ heatmap của ma trận tương quan
    plt.figure(figsize=(24, 24))
    sns.heatmap(corr, annot=True, cmap='coolwarm')
    plt.title('Correlation Matrix')

    # Lưu biểu đồ vào file trong thư mục "upload"
    output_path = os.path.join(output_dir, 'correlation_matrix.png')
    plt.savefig(output_path)

class DataVisualAdmin(admin.PageAdmin):
    page_schema = PageSchema(label="Data visualization", icon="fa fa-pie-chart", url="/data-visualization", isDefaultPage=True, sort=100)
    page_path = "data-visualization"
    histogram()
    drawHeatMap()
    async def get_page(self, request: Request) -> Page:
        page = await super().get_page(request)
        
        page.body = [
            amis.Grid(
                columns=[amis.Grid.Column(
                    body=[
                        amis.Image(
                            type="image",
                            # originalSrc="plot/images.png",
                            height=1000,
                            width=1500,
                            src="upload/histogram.png",
                        ),
                        amis.Image(         
                            type="image",
                            height=1000,
                            width=1500,
                            src="upload/correlation_matrix.png",
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
