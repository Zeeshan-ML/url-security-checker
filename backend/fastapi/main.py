import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import pickle
import os
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import json
from datetime import datetime
from dotenv import load_dotenv
import uvicorn

# Load environment variables from .env file
load_dotenv()

# FastAPI app initialization
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],              # or list your allowed origins
    allow_credentials=True,
    allow_methods=["*"],              # allow all HTTP methods including OPTIONS
    allow_headers=["*"],
)

# Define the input model for the remaining features and URL
class URLFeaturesRequest(BaseModel):
    url: str
    nb_redirection: int
    onmouseover: int
    right_clic: int
    iframe: int
    popup_window: int

# Function to extract URL features
def extract_url_features(url):
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.netloc
    path = parsed_url.path

    # Fetch the webpage for HTML parsing
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Extract hyperlinks (a tags)
    hyperlinks = soup.find_all('a')
    nb_hyperlinks = len(hyperlinks)

    # Extract links within HTML tags
    links_in_tags = sum(1 for tag in soup.find_all(['img', 'script', 'link', 'iframe']) if tag.get('src') or tag.get('href'))

    # Calculate the ratio of internal and external media links (e.g., images, videos)
    int_media_count = 0
    ext_media_count = 0
    for media_tag in soup.find_all(['img', 'video', 'audio']):
        media_url = media_tag.get('src') or media_tag.get('href')
        if media_url:
            parsed_media_url = urllib.parse.urlparse(media_url)
            if parsed_media_url.netloc == hostname:
                int_media_count += 1
            else:
                ext_media_count += 1
    ratio_intMedia = int_media_count / (int_media_count + ext_media_count) if (int_media_count + ext_media_count) > 0 else 0.0
    ratio_extMedia = ext_media_count / (int_media_count + ext_media_count) if (int_media_count + ext_media_count) > 0 else 0.0

    # Check if the anchor tag contains a "safe" link (e.g., HTTPS, valid domain)
    safe_anchor = 0
    for link in hyperlinks:
        href = link.get('href')
        if href and href.startswith('https') and "login" not in href.lower() and "verify" not in href.lower():
            safe_anchor += 1

    features = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hostname) else 0,
        "nb_and": url.count("&"),
        "nb_eq": url.count("="),
        "nb_www": 1 if "www" in hostname else 0,
        "length_words_raw": sum(len(word) for word in re.findall(r'\w+', url)),
        "shortest_word_host": min([len(word) for word in hostname.split(".") if word], default=0),
        "longest_words_raw": max([len(word) for word in re.findall(r'\w+', url)], default=0),
        "longest_word_path": max([len(word) for word in path.split("/") if word], default=0),
        "avg_word_path": sum([len(word) for word in path.split("/") if word]) / (len(path.split("/")) or 1),
        "phish_hints": sum(1 for hint in ["login", "verify", "bank", "secure"] if hint in url.lower()),
        "nb_hyperlinks": nb_hyperlinks,
        "links_in_tags": links_in_tags,
        "ratio_intMedia": ratio_intMedia,
        "ratio_extMedia": ratio_extMedia,
        "safe_anchor": safe_anchor
    }

    return features

# Load your pre-trained model (change the path as necessary)
model_file = os.path.join(os.path.dirname(__file__), "model.pkl")
with open(model_file, "rb") as f:
    model = pickle.load(f)  # Adjust the model path as per your setup

# Function to log to Splunk via HTTP Event Collector
def log_to_splunk(event_data):
    splunk_url = os.getenv('SPLUNK_HEC_URL')
    splunk_token = os.getenv('SPLUNK_HEC_TOKEN')
    headers = {
        'Authorization': f'Splunk {splunk_token}',
        'Content-Type': 'application/json'
    }
    data = {"event": event_data}
    # Disable SSL certificate verification (not recommended for production)
    response = requests.post(splunk_url, headers=headers, data=json.dumps(data), verify=False)
    if response.status_code != 200:
        print("Error logging to Splunk:", response.text)


# FastAPI endpoint to handle the prediction request
@app.post("/predict")
def predict(features: URLFeaturesRequest, request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    if client_ip == "::1":
        client_ip = "127.0.0.1"
    print("Ip Address:",client_ip)
    try:
        # Extract URL features
        url_features = extract_url_features(features.url)
        
        # Combine the extracted URL features with the frontend features
        feature_vector = [
            url_features["length_url"], url_features["length_hostname"], url_features["ip"], url_features["nb_and"],
            url_features["nb_eq"], url_features["nb_www"], url_features["length_words_raw"],
            url_features["shortest_word_host"], url_features["longest_words_raw"], url_features["longest_word_path"],
            url_features["avg_word_path"], url_features["phish_hints"], url_features["nb_hyperlinks"],
            url_features["links_in_tags"],
            url_features["safe_anchor"], features.nb_redirection, features.onmouseover, features.right_clic,
            features.iframe, features.popup_window
        ]

        feature_df = pd.DataFrame([feature_vector], columns=[
            'length_url', 'length_hostname', 'ip', 'nb_and', 'nb_eq', 'nb_www',
            'length_words_raw', 'shortest_word_host', 'longest_words_raw',
            'longest_word_path', 'avg_word_path', 'phish_hints', 'nb_hyperlinks',
            'links_in_tags','safe_anchor',
            'nb_redirection', 'onmouseover', 'right_clic', 'iframe', 'popup_window'
        ])

        # Predict using the model
        prediction = model.predict(feature_df)
        
        # Determine the result based on prediction
        if prediction[0] == 0:
            result_text = "Safe"
            print("Safe")
        elif prediction[0] == 1:
            result_text = "Malicious"
            print("Malicious")
        else:
            raise HTTPException(status_code=500, detail="Unexpected prediction result.")
        
        # Log the prediction event to Splunk
        log_event = {
            "event": "ML Prediction",
            "url": features.url,
            "extractedFeatures": url_features,
            "client_ip": client_ip,
            "frontendFeatures": {
                "nb_redirection": features.nb_redirection,
                "onmouseover": features.onmouseover,
                "right_clic": features.right_clic,
                "iframe": features.iframe,
                "popup_window": features.popup_window
            },
            "prediction": result_text,
            "timestamp": datetime.utcnow().isoformat()
        }
        log_to_splunk(log_event)
        
        return {"prediction": result_text}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=7000, reload=True)

