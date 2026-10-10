import requests
import os

BASE_URL = "http://127.0.0.1:5000"

username = input("Username: ")
password = input("Password: ")

login_response = requests.post(
    f"{BASE_URL}/api/login",
    json={
        "username": username,
        "password": password
    }
)

print("LOGIN STATUS:", login_response.status_code)
print("LOGIN RESPONSE:", login_response.text)

login_data = login_response.json()
token = login_data.get("token")

if not token:
    print("No token received.")
    exit()

url = f"{BASE_URL}/api/download/sample_stego.png"

response = requests.get(
    url,
    headers={
        "Authorization": f"Bearer {token}"
    },
    stream=True
)

print("DOWNLOAD STATUS:", response.status_code)
print("HEADERS:", response.headers)

received = 0

with open("test_download.png", "wb") as f:
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:
            f.write(chunk)
            received += len(chunk)

print("HTTP CONTENT-LENGTH:", response.headers.get("Content-Length"))
print("RECEIVED BYTES:", received)

if os.path.exists("test_download.png"):
    print("SAVED FILE SIZE:", os.path.getsize("test_download.png"))