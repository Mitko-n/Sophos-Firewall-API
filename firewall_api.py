import requests
import xmltodict
from jinja2 import Template

# Constants for filter criteria
EQ = "="
NOT = "!="
LIKE = "like"

class Firewall:
    # Dictionary holding templates for different operations
    templates_dict = {
        "create": """<Set operation="add"><{{ entity_type }}>{{ entity_data | safe }}</{{ entity_type }}></Set>""",
        "read": """<Get><{{ entity_type }}>{% if entity_data %}<Filter><key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key></Filter>{% endif %}</{{ entity_type }}></Get>""",
        "update": """<Set operation="update"><{{ entity_type }}>{{ entity_data | safe }}</{{ entity_type }}></Set>""",
        "delete": """<Remove><{{ entity_type }}>{% if entity_type == "FirewallRule" %}<Name>{{ entity_data }}</Name>{% else %}{% if entity_data %}<Filter><key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key></Filter>{% endif %}{% endif %}</{{ entity_type }}></Remove>""",
        "url": """https://{{ hostname }}:{{ port }}/webconsole/APIController""",
        "login": """<Login><Username>{{ username }}</Username><Password{% if password_encrypted %} passwordform='encrypt'{% endif %}>{{ password }}</Password></Login>""",
    }

    def __init__(self, username, password, hostname, port=4444, certificate_verify=False, password_encrypted=False):
        # Initialize the URL and login XML using templates
        self.url = Template(self.templates_dict["url"]).render(hostname=hostname, port=port)
        self.xml_login = Template(self.templates_dict["login"]).render(username=username, password=password, password_encrypted=password_encrypted)
        
        # Create a session object for persistent connections
        self.session = requests.Session()
        self.session.verify = certificate_verify
        self.headers = {"Accept": "application/xml"}
        
        # Suppress warnings if certificate verification is disabled
        if not certificate_verify:
            requests.packages.urllib3.disable_warnings()

    def __enter__(self):
        # Enable the use of the 'with' statement
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Ensure the session is closed when exiting the 'with' statement
        self.session.close()

    def _format_xml_response(self, response, entity_type):
        # Check for authentication failure
        login = response["Response"].get("Login")
        if login and login.get("status") == "Authentication Failure":
            return {"data": [], "code": "401", "text": login["status"]}

        # Check for status in response
        status = response["Response"].get("Status")
        if status:
            return {"data": [], "code": status["@code"], "text": status["#text"]}

        # Extract the relevant entity response
        entity_response = response["Response"].get(entity_type, [])
        
        # Handle status within entity response
        if "Status" in entity_response:
            status = entity_response["Status"]
            if isinstance(status, str):
                status = {"@code": "", "#text": status}
            code = status.get("@code")
            if code:
                return {"data": [], "code": code, "text": status.get("#text")}
            elif status.get("#text") == "No. of records Zero.":
                return {"data": [], "code": "526", "text": "Record does not exist."}

        # Clean up the entity response by removing transaction ID if present
        entity_response = [entity_response] if isinstance(entity_response, dict) else entity_response
        entity_response = [{k: v for k, v in item.items() if k != "@transactionid"} for item in entity_response]

        return {"data": entity_response, "code": "216", "text": "Operation Successful."}

    def _perform_action(self, action_key, entity_type, entity_data=None, filter_selector=None):
        # Render the action template with provided data
        action = Template(self.templates_dict[action_key])
        xml_action = action.render(entity_type=entity_type, entity_data=entity_data, filter_selector=filter_selector)

        # Create the complete XML request
        xml_request = f"<Request>{self.xml_login}{xml_action}</Request>"
        
        # Perform the HTTP POST request
        response = self.session.post(self.url, headers=self.headers, data={"reqxml": xml_request}, timeout=30)

        if response:
            # Format the response and return
            return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)
        else:
            # Handle the case where no response is returned
            return {"data": [], "code": str(response.status_code), "text": response.reason}

    def create(self, entity_type, entity_data):
        # Convert entity_data dictionary to XML string
        entity_data = xmltodict.unparse(entity_data, full_document=False)
        return self._perform_action("create", entity_type, entity_data)

    def read(self, entity_type, entity_name=None, filter_selector=LIKE):
        # Perform read operation with optional filtering
        return self._perform_action("read", entity_type, entity_name, filter_selector)

    def update(self, entity_type, entity_data):
        # Convert entity_data dictionary to XML string
        entity_data = xmltodict.unparse(entity_data, full_document=False)
        return self._perform_action("update", entity_type, entity_data)

    def delete(self, entity_type, entity_name=None, filter_selector=EQ):
        # Perform delete operation with optional filtering
        return self._perform_action("delete", entity_type, entity_name, filter_selector)
