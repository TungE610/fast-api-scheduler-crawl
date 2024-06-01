# Install dependencies
pip install fastapi uvicorn fastapi_amis_admin fastapi_scheduler

# Run server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# See in browser:
http://localhost:8001/admin
