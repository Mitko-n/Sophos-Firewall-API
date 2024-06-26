import requests
import xmltodict
from jinja2 import Template

# Define filter selectors
EQ = "="
NOT = "!="
LIKE = "like"


class Firewall:

    # Templates for different API actions
    templates_dict = {
        "create": """
            <Set operation="add">
                <{{ entity_type }}>{{ entity_data | safe }}</{{ entity_type }}>
            </Set>
        """,
        "read": """
            <Get>
                <{{ entity_type }}>
                    {% if entity_data %}
                        <Filter>
                            <key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key>
                        </Filter>
                    {% endif %}
                </{{ entity_type }}>
            </Get>
        """,
        "update": """
            <Set operation="update">
                <{{ entity_type }}>{{ entity_data | safe }}</{{ entity_type }}>
            </Set>
        """,
        "delete": """
            <Remove>
                <{{ entity_type }}>
                    {% if entity_type == "FirewallRule" %}
                        <Name>{{ entity_data }}</Name>
                    {% else %}
                        {% if entity_data %}
                            <Filter>
                                <key name="Name" criteria="{{ filter_selector }}">{{ entity_data }}</key>
                            </Filter>
                        {% endif %}
                    {% endif %}
                </{{ entity_type }}>
            </Remove>
        """,
    }

    def __init__(self, username, password, hostname, port=4444, certificate_verify=False, password_encrypted=False):
        # Rendering URL and login XML templates with provided data
        self.url = f"https://{hostname}:{port}/webconsole/APIController"
        self.xml_login = f"""
            <Login> 
                <Username>{username}</Username>
                    <Password{" passwordform='encrypt'" if password_encrypted else ""}>{password}</Password>
            </Login>
        """

        # Setting up requests session
        self.session = requests.Session()
        self.session.verify = certificate_verify
        self.headers = {"Accept": "application/xml"}
        # Disable SSL warnings if certificate verification is disabled
        if not certificate_verify:
            requests.packages.urllib3.disable_warnings()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Close the session when exiting the context
        self.session.close()

    def _send_xml_request(self, xmldata):
        # Send XML request and return the response
        return self.session.post(self.url, headers=self.headers, data={"reqxml": xmldata}, timeout=30)

    def _format_xml_response(self, response, entity_type):
        # Format XML response data for readability and ease of use
        # Check for general status in the main response

        response = response["Response"]

        if "Status" in response:
            return {"data": [], "code": response["Status"]["@code"], "text": response["Status"]["#text"]}

        # Check for authentication failure in the login response
        if response["Login"] and response["Login"]["status"] == "Authentication Failure":
            return {"data": [], "code": "401", "text": response["Login"]["status"]}

        # Check for entity-specific status and data
        if entity_type in response:
            entity_data = response[entity_type]
            if "Status" in entity_data:
                if "@code" in entity_data["Status"]:
                    return {"data": [], "code": entity_data["Status"]["@code"], "text": entity_data["Status"]["#text"]}
                elif entity_data["Status"] in ["No. of records Zero.", "Number of records Zero."]:
                    return {"data": [], "code": "526", "text": f"Record does not exist."}

            # Prepare and clean the entity response data
            entity_data = [entity_data] if isinstance(entity_data, dict) else entity_data
            entity_data = [{k: v for k, v in item.items() if k != "@transactionid"} for item in entity_data]

            return {"data": entity_data, "code": "216", "text": "Operation Successful."}

        # Default case if entity_type is not found
        return {"data": [], "code": "404", "text": "Entity not found"}  # NOT CLEAR IF WE NEED THIS

    def _perform_action(self, action_template_key, entity_type, entity_data=None, filter_selector=None):
        # Perform an action (CRUD) using the provided template and data
        template_action = Template(self.templates_dict[action_template_key])
        xml_action = template_action.render(entity_type=entity_type, entity_data=entity_data, filter_selector=filter_selector)
        full_request_xml = f"<Request>{self.xml_login}{xml_action}</Request>"
        response = self._send_xml_request(full_request_xml)
        if response:
            return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)
        else:
            return {"data": [], "code": response.status_code, "text": response.reason}

    def create(self, entity_type, entity_data):
        # Create a new entity
        xml_data = xmltodict.unparse(entity_data, full_document=False)
        return self._perform_action("create", entity_type, entity_data=xml_data)

    def read(self, entity_type, entity_data=None, filter_selector=LIKE):
        # Read entity/entities
        return self._perform_action("read", entity_type, entity_data, filter_selector)

    def update(self, entity_type, entity_data):
        # Update an existing entity
        xml_data = xmltodict.unparse(entity_data, full_document=False)
        return self._perform_action("update", entity_type, entity_data=xml_data)

    def delete(self, entity_type, entity_data=None, filter_selector=EQ):
        # Delete an entity/entities
        return self._perform_action("delete", entity_type, entity_data, filter_selector)
