import requests
import xmltodict
from jinja2 import Template

EQ = "="
NOT = "!="
LIKE = "like"


class Firewall:
    templates_dict = {
        "create": """<Set operation="add"><{{ entity_type }}>{{ entity_data | safe }}</{{ entity_type }}></Set>""",
        "read": """<Get><{{ entity_type }}>{% if entity_data %}<Filter><key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key></Filter>{% endif %}</{{ entity_type }}></Get>""",
        "update": """<Set operation="update"><{{ entity_type }}>{{ entity_data | safe }}</{{ entity_type }}></Set>""",
        "delete": """<Remove><{{ entity_type }}>{% if entity_type == "FirewallRule" %}<Name>{{ entity_data }}</Name>{% else %}{% if entity_data %}<Filter><key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key></Filter>{% endif %}{% endif %}</{{ entity_type }}></Remove>""",
        "url": """https://{{ hostname }}:{{ port }}/webconsole/APIController""",
        "login": """<Login><Username>{{ username }}</Username><Password{% if password_encrypted %} passwordform='encrypt'{% endif %}>{{ password }}</Password></Login>""",
    }

    def __init__(self, username, password, hostname, port=4444, certificate_verify=False, password_encrypted=False):
        self.url = Template(self.templates_dict["url"]).render(hostname=hostname, port=port)
        self.xml_login = Template(self.templates_dict["login"]).render(username=username, password=password, password_encrypted=password_encrypted)
        self.session = requests.Session()
        self.session.verify = certificate_verify
        self.headers = {"Accept": "application/xml"}
        if not certificate_verify:
            requests.packages.urllib3.disable_warnings()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.close()

    def _format_xml_response(self, response, entity_type):

        login = response["Response"].get("Login")
        if login and login.get("status") == "Authentication Failure":
            return {"data": [], "code": "401", "text": login["status"]}

        status = response["Response"].get("Status")
        if status:
            return {"data": [], "code": status["@code"], "text": status["#text"]}

        entity_response = response["Response"].get(entity_type, [])
        if "Status" in entity_response:
            status = entity_response["Status"]
            if isinstance(status, str):
                status = {"@code": "", "#text": status}
            code = status.get("@code")
            if code:
                return {"data": [], "code": code, "text": status.get("#text")}
            elif status.get("#text") == "No. of records Zero.":
                return {"data": [], "code": "526", "text": "Record does not exist."}

        entity_response = [entity_response] if isinstance(entity_response, dict) else entity_response
        entity_response = [{k: v for k, v in item.items() if k != "@transactionid"} for item in entity_response]

        return {"data": entity_response, "code": "216", "text": "Operation Successful."}

    def _perform_action(self, action_key, entity_type, entity_data=None, filter_selector=None):

        action = Template(self.templates_dict[action_key])
        xml_action = action.render(entity_type=entity_type, entity_data=entity_data, filter_selector=filter_selector)

        xml_request = f"<Request>{self.xml_login}{xml_action}</Request>"
        response = self.session.post(self.url, headers=self.headers, data={"reqxml": xml_request}, timeout=30)

        if response:
            return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)
        else:
            return {"data": [], "code": response.status_code, "text": response.reason}

    def create(self, entity_type, entity_data):
        entity_data = xmltodict.unparse(entity_data, full_document=False)
        return self._perform_action("create", entity_type, entity_data)

    def read(self, entity_type, entity_name=None, filter_selector=LIKE):
        return self._perform_action("read", entity_type, entity_name, filter_selector)

    def update(self, entity_type, entity_data):
        entity_data = xmltodict.unparse(entity_data, full_document=False)
        return self._perform_action("update", entity_type, entity_data)

    def delete(self, entity_type, entity_name=None, filter_selector=EQ):
        return self._perform_action("delete", entity_type, entity_name, filter_selector)
