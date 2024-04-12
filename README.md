# Simple Sophos Firewall API 
#### version v 0.5.0
#
## General Informatin
The Sophos Firewall API is a tool that simplifies the management of Sophos Firewall systems. It follows the CRUD specification, which means that it allows you to create, read, update, and delete firewall entities. While the API is designed to make your daily firewall management tasks easier, it's important to note that there is no guarantee that everything will run seamlessly. You are free to use our code, but please remember that any responsibility for usage falls solely on the user.

***NOTE:***
Sophos Firewall API is still under development.

***Currente library***  
**sophos_firewall_api.py**&nbsp; &nbsp;Utilises ***request*** library.  
**firewall_api.py**&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp; &nbsp; &nbsp; &nbsp;It utilizes the ***Jinja2*** library and can be used with the context manager and its own request templates. It supports better error and request/response handling.
 
#
## How to Use
To view the entity structure, utilize the **```read(entity_type)```** method.\
The response obtained from this method can be used to generate data for the **```create(entity_type, entity_data)```** and **```update(entity_type, entity_data)```** methods.\
It's worth noting that while the syntax for **```read()```** and **```delete()```** are similar, their operations differ.
#
## Sophos Firewall password encryption

From Advanced Shell run:
```
aes-128-cbc-tool -k Th1s1Ss1mPlygR8API -t 1 -s <PASSWORD>
```
#
## Firewall CRUD API Description

### Entity Type
```python
entity_type = "FirewallRule"
entity_type = "IPHost"
```

For additional information check **entity_type.txt** file.
### Respone Format
API response is Python Diction with following format:
```python
response = {
    "data":[
        {...},
        {...},
        ...,
        ], 
    "code":"<RESULT_CODE>", 
    "text":"<RESULT_DESCRIPTION_TEXT>",
    }
```

List of data elements:  **```response["data"]```**\
First data element: **```response["data"][0]```**\
Result code: **```response["code"]```**\
Result description text: **```response["text"]```**

### Imports
```python
from sophos_firewall_api import Firewall, EQ, NOT, LIKE
```
or
```python
from firewall_api import Firewall, EQ, NOT, LIKE
```
### Initialization with context manager
```python
from firewall_api import Firewall, EQ, NOT, LIKE

with Firewall(username, password, firewall_ip, port=4444, certificate_verify=False, password_encrypted=False) as firewall:
    response = firewall.read(entity_type)
    # add your code here
```
### Initialization without context manager
```python
from sophos_firewall_api import Firewall, EQ, NOT, LIKE

firewall = Firewall(username, password, firewall_ip)
firewall = Firewall(username, password, firewall_ip, password_encrypted=True)
firewall = Firewall(username, password, firewall_ip, port, certificate_verify=True, password_encrypted=True)
```

### You can use only
```python
 firewall = Firewall(username, password, firewall_ip)
```

### CREATE Entity
Create entity with type **entity_type** from provided **entity_data**.
```python
response = firewall.create(entity_type, entity_data)
```
Some **entity_types** have additional **data_entity** that is required for the creation of the entity.
### READ Entity
Read entity with type **entity_type** and name **entity_name**. You can use **filter_type** for partial read.
```python
response = firewall.read(entity_type)
response = firewall.read(entity_type, entity_name)
response = firewall.read(entity_type, entity_name, filter_type)
```

### UPDATE Entity
Update entity with type **entity_type** with provided **entity_data**.
```python
response = firewall.update(entity_type, entity_data)
```
### DELETE Entity
Delete entity with type **entity_type** and name **entity_name**. You can use **filter_type** for bulk deletion.
```python
response = firewall.delete(entity_type, entity_name)
response = firewall.delete(entity_type, entity_name, filter_type)
```
### Filter Type

```python
EQ      # matches entities with an exact name match
NOT     # matches entities where the name does not match at all
LIKE    # matches entities with partial name matches
```
Filter Type is used for ***Read*** and ***Delete*** operations and applies to **entity_name**.\
Default Filter Type for ***Read Entity*** is **LIKE** and\
Default Filter Type for ***Delete Entity*** is ***EQ***.

## Examples
### Read/Download Entiy/Template
```python
response = firewall.read(entity_type)

response["code"]    # Result Code
response["text"]    # Result Description Text
response["data"]    # Result Data (List of Dict)
```
### Print All **IPHost**
```python
username = "<USER_NAME>"
password = "<PASSWORD>"
firewall_ip = "<IP_ADDRESS>"

firewall = Firewall(username, password, firewall_ip)

entity_type = "IPHost"

response = firewall.read(entity_type)
print("Code:", response["code"], "Text:", response["text"])
for index, item in enumerate(response["data"], start=1):
    print(f"{index:002}: {item}")
```
### Create **IPHost**
```python
username = "<USER_NAME>"
password = "<PASSWORD>"
firewall_ip = "<IP_ADDRESS>"

firewall = Firewall(username, password, firewall_ip)

entity_type = "IPHost"
entity_data = {
    "Name": "Host_172.16.17.100",
    "HostType": "IP",
    "IPAddress": "172.16.17.100",
}

firewall.create(entity_type, entity_data)
```
### Read all **FirewallRules**
```python
username = "<USER_NAME>"
password = "<PASSWORD>"
firewall_ip = "<IP_ADDRESS>"

firewall = Firewall(username, password, firewall_ip)

entity_type = "FirewallRule"

response = firewall.read(entity_type)

print("Code:", response["code"], "Text:", response["text"])
for index, item in enumerate(response["data"], start=1):
    print(f"{index:03}: {item}")
```
### Read all **IPHost** entities with **entity_name** in the Name
```python
username = "<USER_NAME>"
password = "<PASSWORD>"
firewall_ip = "<IP_ADDRESS>"

firewall = Firewall(username, password, firewall_ip)
entity_type = "IPHost"
entity_name = "Internet"

print(f"\nREAD :: {entity_type} entity with {entity_name} in the 'Name'")
response = firewall.read(entity_type, entity_name)    # LIKE by Default
print("Code:", response["code"], "Text:", response["text"])
for index, item in enumerate(response["data"], start=1):
    print(f"{index:03}: {item}")

```