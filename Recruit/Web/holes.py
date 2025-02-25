import requests

url = 'http://recruit.osiris.bar:32004'

response = requests.get(f"{url}/.hole/flag.txt")
print(response.text)

# flag{hopefully_the_hole_wasnt_too_deep}
