# import vt

# client = vt.Client("316fc5b179ab03baf0b742519e1e271b1912c2fe073849df40c1b54ffba16c48")
import base64
def encode_url(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")

import requests


url_id = encode_url("https://www.virustotal.com/")
print(url_id)
url = f"https://www.virustotal.com/api/v3/urls/"
# payload = { "url": "https://www.virustotal.com/" ,"id": "u-f1177df4692356280844e1d5af67cc4a9eccecf77aa61c229d483b7082c70a8e-1739860750"}
headers = {
    "accept": "application/json",
    "x-apikey": "316fc5b179ab03baf0b742519e1e271b1912c2fe073849df40c1b54ffba16c48",
    
}

response = requests.get(url, headers=headers)

print(response.text)