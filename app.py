import sys
import os
import json
import io
from datetime import datetime
from functools import lru_cache
import socket
import re
import requests
import whois
import datetime as dt
import joblib

import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGODB_URL_KEY")

import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logger
from networksecurity.pipeline.training_pipeline import TrainingPipeline

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile, Request, Body, HTTPException
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object
from networksecurity.utils.ml_utils.model.estimator import NetworkModel

from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ------------------ MongoDB setup ------------------
# NOTE: The client setup will fail if MONGODB_URL_KEY is not set or accessible.
# However, this is outside the scope of the current Type Error fixes.
client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)
from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME, DATA_INGESTION_DATABASE_NAME

database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

# ------------------ FastAPI app ------------------
app = FastAPI(title="Network Security Analyzer", version="2.0")
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["root"])
async def index():
    return RedirectResponse(url="/docs")

@app.get("/train")
async def train_route():
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        logger.info("Training is successful")
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e, sys)

# ------------------ Model registry helper ------------------
MODEL_REGISTRY_FILE = "MODEL_REGISTRY.json"
DEFAULT_PREPROCESSOR_PATH = "final_model/preprocessor.pkl"
DEFAULT_MODEL_PATH = "final_model/model.pkl"

def read_model_registry():
    if os.path.exists(MODEL_REGISTRY_FILE):
        try:
            with open(MODEL_REGISTRY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def get_registry_paths():
    r = read_model_registry()
    model_path = r.get("active_model", os.getenv("ACTIVE_MODEL_PATH", DEFAULT_MODEL_PATH))
    preproc_path = r.get("preprocessor", os.getenv("PREPROCESSOR_PATH", DEFAULT_PREPROCESSOR_PATH))
    return preproc_path, model_path

@lru_cache(maxsize=1)
def load_network_model():
    preproc_path, model_path = get_registry_paths()
    preprocessor = load_object(preproc_path)
    model = load_object(model_path)
    return NetworkModel(preprocessor=preprocessor, model=model)

# ------------------ CSV batch prediction ------------------
@app.post("/predict", tags=["batch"])
async def predict_route(request: Request, file: UploadFile = File(...)):
    try:
        df = pd.read_csv(file.file)
        network_model = load_network_model()
        y_pred = network_model.predict(df)
        df['predicted_column'] = y_pred

        # FIX 2: Create prediction directory if it doesn't exist to prevent OSError
        output_dir = 'prediction_output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        df.to_csv(f'{output_dir}/output.csv', index=False)
        table_html = df.to_html(classes='table table-striped')
        return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
    except Exception as e:
        raise NetworkSecurityException(e, sys)

# ------------------ Feature extraction ------------------
REQUEST_TIMEOUT = 4
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "adf.ly", "is.gd", "tiny.cc"}

def safe_parse(url):
    try: return urlparse(url)
    except: return None

def having_ip_address(url): 
    try:
        domain = urlparse(url).netloc
        return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else -1
    except: return -1

def url_length(url): 
    l = len(url)
    return -1 if l >= 75 else (0 if 54 <= l < 75 else 1)

def shortening_service(url): 
    return 1 if any(s in url for s in SHORTENERS) else -1

def having_at_symbol(url): return 1 if "@" in url else -1
def double_slash_redirecting(url): return 1 if url.rfind("//") > 6 else -1
def prefix_suffix(url): return -1 if "-" in urlparse(url).netloc else 1
def having_sub_domain(url): return -1 if urlparse(url).netloc.count('.') > 2 else 1
def ssl_final_state(url): return 1 if url.startswith("https") else -1

def domain_registration_length(url):
    try:
        d = urlparse(url).netloc
        w = whois.whois(d)
        if w.expiration_date:
            exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            return -1 if (exp - dt.datetime.now()).days <= 365 else 1
    except: return -1
    return -1   

def favicon(url):
    try:
        domain = urlparse(url).netloc
        r = requests.get(f"http://{domain}/favicon.ico", timeout=REQUEST_TIMEOUT)
        return 1 if r.status_code == 200 else -1
    except: return -1

# FIX 1: Renamed 'port' feature extraction function to avoid collision with 'port' variable below.
def check_port_feature(url):
    try:
        domain = urlparse(url).netloc
        socket.create_connection((domain, 80), timeout=2)
        return 1
    except: return -1

def https_token(url): return -1 if "https" in urlparse(url).netloc else 1
def request_url(url): return 1 if url.startswith("https") else -1
def url_of_anchor(url): return 1   # simplified
def links_in_tags(url): return 1
def sfh(url): return -1 if url == "" or url.lower() == "about:blank" else 1
def submitting_to_email(url): return -1 if "mailto:" in url else 1
def abnormal_url(url):
    try:
        socket.gethostbyname(urlparse(url).netloc)
        return 1
    except: return -1
def redirect(url):
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        return -1 if len(r.history) > 2 else 1
    except: return -1
def on_mouseover(url): return -1
def right_click(url): return 1
def popup_window(url): return -1
def iframe(url): return -1
def age_of_domain(url):
    try:
        d = urlparse(url).netloc
        w = whois.whois(d)
        if w.creation_date:
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            return -1 if (dt.datetime.now() - creation).days < 180 else 1
    except: return -1
    return -1
def dns_record(url):
    try:
        socket.gethostbyname(urlparse(url).netloc)
        return 1
    except: return -1

# external / stubbed
def web_traffic(url): return 0
def page_rank(url): return 0
def google_index(url): return 1
def links_pointing_to_page(url): return -1
def statistical_report(url): return -1

FEATURE_COLUMNS = [
 "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol","double_slash_redirecting",
 "Prefix_Suffix","having_Sub_Domain","SSLfinal_State","Domain_registeration_length","Favicon","port",
 "HTTPS_token","Request_URL","URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
 "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain","DNSRecord","web_traffic",
 "Page_Rank","Google_Index","Links_pointing_to_page","Statistical_report"
]

def extract_features(url: str):
    return {
        "having_IP_Address": having_ip_address(url),
        "URL_Length": url_length(url),
        "Shortining_Service": shortening_service(url),
        "having_At_Symbol": having_at_symbol(url),
        "double_slash_redirecting": double_slash_redirecting(url),
        "Prefix_Suffix": prefix_suffix(url),
        "having_Sub_Domain": having_sub_domain(url),
        "SSLfinal_State": ssl_final_state(url),
        "Domain_registeration_length": domain_registration_length(url),
        "Favicon": favicon(url),
        "port": check_port_feature(url), # FIX 1: Calling the renamed function
        "HTTPS_token": https_token(url),
        "Request_URL": request_url(url),
        "URL_of_Anchor": url_of_anchor(url),
        "Links_in_tags": links_in_tags(url),
        "SFH": sfh(url),
        "Submitting_to_email": submitting_to_email(url),
        "Abnormal_URL": abnormal_url(url),
        "Redirect": redirect(url),
        "on_mouseover": on_mouseover(url),
        "RightClick": right_click(url),
        "popUpWidnow": popup_window(url),
        "Iframe": iframe(url),
        "age_of_domain": age_of_domain(url),
        "DNSRecord": dns_record(url),
        "web_traffic": web_traffic(url),
        "Page_Rank": page_rank(url),
        "Google_Index": google_index(url),
        "Links_pointing_to_page": links_pointing_to_page(url),
        "Statistical_report": statistical_report(url),
    }

# ------------------ Real-time analyze ------------------
@app.post("/analyze", tags=["analysis"])
async def analyze(payload: dict = Body(...)):
    try:
        url = payload.get("url")
        if not url:
            raise HTTPException(status_code=400, detail="Missing 'url' in request")

        feats = extract_features(url)
        df = pd.DataFrame([feats])[FEATURE_COLUMNS]

        network_model = load_network_model()
        pred = network_model.predict(df)[0]

        response = {"url": url, "features": feats, "prediction": int(pred)}

        try:
            database["predictions_log"].insert_one({
                "timestamp": datetime.utcnow().isoformat(),
                "url": url,
                "features": feats,
                "prediction": response["prediction"]
            })
        except Exception as e:
            logger.error(f"Mongo logging failed: {e}")

        return response
    except Exception as e:
        # NOTE: If this exception is a NetworkSecurityException, the error message from the root cause 
        # (like 'int' object is not callable) is being captured and propagated.
        # This is where the fix above prevents the "TypeError" from being caught.
        raise NetworkSecurityException(e, sys)

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    # This line defines the integer variable 'port' that conflicted with the 'port' function.
    port = int(os.getenv("PORT", 8080))
    app_run(app, host=host, port=port)