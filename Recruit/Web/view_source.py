import requests

url = 'http://recruit.osiris.bar:32000'

response = requests.get(url)
print(response.text)

# flag{th@t_wuz_ez}
