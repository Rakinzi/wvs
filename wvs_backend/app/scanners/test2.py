import requests
import time

API_URL = "https://api-inference.huggingface.co/models/HuggingFaceH4/zephyr-7b-beta"
headers = {"Authorization": "Bearer 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"}  # Replace with actual key

def query_with_retry(prompt, max_retries=3):
    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 200,
            "wait_for_model": True
        }
    }
    
    for _ in range(max_retries):
        response = requests.post(API_URL, headers=headers, json=payload)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 503:
            print("Model loading... retrying in 10s")
            time.sleep(10)
        else:
            raise Exception(f"API Error: {response.text}")
    
    raise Exception("Max retries exceeded")

response = query_with_retry("Who's Eobard Thawne")
print(response[0]['generated_text'])