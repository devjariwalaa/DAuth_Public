import os
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecretkey")
ALGORITHM = "HS256" 
ACCESS_TOKEN_EXPIRE_MINUTES = 1