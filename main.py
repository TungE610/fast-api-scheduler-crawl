from fastapi import FastAPI
from fastapi_amis_admin.admin.settings import Settings
from fastapi_amis_admin import i18n
i18n.set_language(language='en_US')
from fastapi_amis_admin.admin.site import AdminSite
from datetime import date
from fastapi_scheduler import SchedulerAdmin
from crawler import Phisherman

# Create `FastAPI` application
app = FastAPI()

# Create `AdminSite` instance
site = AdminSite(settings=Settings(debug=True, database_url_async='sqlite+aiosqlite:///amisadmin.db'))

# Create an instance of the scheduled task scheduler `SchedulerAdmin`
scheduler = SchedulerAdmin.bind(site)

last_crawler_url_id = "8575641"

# Add scheduled tasks, refer to the official documentation: https://apscheduler.readthedocs.io/en/master/
# use when you want to run the job at fixed intervals of time
@scheduler.scheduled_job('interval', seconds=200000, max_instances=2)
def crawl_phishing_url_from_phishing_tank():
    global last_crawler_url_id
    start, end = 1, 1

    with Phisherman(start, end) as phisherman:
        last_crawler_url_id = phisherman.crawl(last_crawler_url_id)
        print("last crawled index: ")
        print(last_crawler_url_id)

@scheduler.scheduled_job('interval', seconds=10, max_instances=2)
def crawl_legitimate_url_from_common_crawl():
    print(Phisherman(1, 1).get_crawler_codes())
   

# use when you want to run the job periodically at certain time(s) of day
@scheduler.scheduled_job('cron', hour=3, minute=30)
def cron_task_test():
    print('cron task is run...')

# use when you want to run the job just once at a certain point of time
@scheduler.scheduled_job('date', run_date=date(2022, 11, 11))
def date_task_test():
    print('date task is run...')

site.mount_app(app)

@app.on_event("startup")
async def startup():
    # Mount the background management system
    # Start the scheduled task scheduler
    scheduler.start()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, debug=True)
