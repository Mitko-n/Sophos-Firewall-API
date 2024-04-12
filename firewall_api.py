import requests
import xmltodict
from jinja2 import Template

EQ = "="
NOT = "!="
LIKE = "like"


class Firewall:
    
    def __init__(self, username, password, hostname, port=4444, certificate_verify=False, password_encrypted=False):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.certificate_verify = certificate_verify
        self.password_encrypted = password_encrypted
        self.url = f"https://{hostname}:{port}/webconsole/APIController"
        self.headers = {"Accept": "application/xml"}
        self.xml_login = f"<Login><Username>{username}</Username><Password{" passwordform='encrypt'" if password_encrypted else ""}>{password}</Password></Login>"
       
        self.session = requests.Session()
        if not self.certificate_verify:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()


    def __enter__(self):
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        if self.session:
            self.session.close()
  

    def _send_xml_request(self, xmldata):
            return self.session.post(self.url, headers=self.headers, data={"reqxml": xmldata}, timeout=30)
 

    def _format_xml_response(self, response, entity_type):
        if "Status" in response["Response"]:
            status = response["Response"]["Status"]
            if isinstance(status, str):
                status = {"@code": "", "#text": status}
            return {"data": [], "code": status["@code"], "text": status["#text"]}


        login = response["Response"]["Login"]
        if login["status"] == "Authentication Failure":
            return {"data": [], "code": "401", "text": login["status"]}

        if "Login" in response["Response"] and entity_type in response["Response"]:
            entity_type_response = response["Response"][entity_type]
            if isinstance(entity_type_response, dict) or isinstance(entity_type_response, list):
                if isinstance(entity_type_response, dict):
                    entity_type_response = [entity_type_response]
                for item in entity_type_response:
                    if "Status" in item:
                        status = item["Status"]
                        if isinstance(status, str):
                            status = {"@code": "", "#text": status}
                        code = status.get("@code")
                        if code:
                            return {"data": [], "code": code, "text": status.get("#text")}
                        elif status.get("#text") == "No. of records Zero.":
                            return {"data": [], "code": "526", "text": "Record does not exist."}

        entity_type_data = response["Response"].get(entity_type)
        response_data = [entity_type_data] if isinstance(entity_type_data, dict) else entity_type_data
        for item in response_data:
            item.pop("@transactionid", None)

        return {"data": response_data, "code": "216", "text": "Operation Successful."}


    def _perform_action(self, action_template_key, entity_type, entity_data=None, filter_selector=None):
       
        template_str = self.templates_dict.get(action_template_key)
        if not template_str:
            raise ValueError(f"No template found for action: {action_template_key}")

        template = Template(template_str)
        xml_action = template.render(entity_type=entity_type, entity_data=entity_data, filter_selector=filter_selector)
        response = self._send_xml_request(f"<Request>{self.xml_login}{xml_action}</Request>")
        if response:
            return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)
        else:
            return {"data": [], "code": response.status_code, "text": response.reason}
 
    
    templates_dict = {
        "create": """<Set operation="add"><{{ entity_type }}>
                                                {{ entity_data | safe }}
                                            </{{ entity_type }}>
                    </Set>""",
        "read": """<Get><{{ entity_type }}>
                            {% if entity_data %}
                                <Filter><key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key></Filter>
                            {% endif %}
                        </{{ entity_type }}>
                    </Get>""",
        "update": """<Set operation="update"><{{ entity_type }}>
                                                {{ entity_data | safe }}
                                            </{{ entity_type }}>
                    </Set>""",
        "delete": """<Remove><{{ entity_type }}>
                                {% if entity_type == "FirewallRule" %}
                                    <Name>{{ entity_data }}</Name>
                                {% else %}
                                    {% if entity_data %}
                                        <Filter><key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key></Filter>
                                    {% endif %}
                                {% endif %}
                            </{{ entity_type }}>
                    </Remove>"""
    
    }

    def create(self, entity_type, entity_data):
        return self._perform_action("create", entity_type, entity_data=xmltodict.unparse(entity_data, full_document=False))


    def read(self, entity_type, entity_data=None, filter_selector=LIKE):
        return self._perform_action("read", entity_type, entity_data=entity_data, filter_selector=filter_selector)


    def update(self, entity_type, entity_data):
        return self._perform_action("update", entity_type, entity_data=xmltodict.unparse(entity_data, full_document=False))


    def delete(self, entity_type, entity_data=None, filter_selector=EQ):
        return self._perform_action("delete", entity_type, entity_data=entity_data, filter_selector=filter_selector)
