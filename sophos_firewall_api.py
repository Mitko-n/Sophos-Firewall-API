import requests
import xmltodict


EQ = "="  # matches entities with an exact name match
NOT = "!="  # matches entities where the name does not match at all
LIKE = "like"  # matches entities with partial name matches


class Firewall:
    def __init__(self, username, password, hostname, port=4444, certificate_verify=False, password_encrypted=False):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.certificate_verify = certificate_verify

        if not certificate_verify:
            requests.packages.urllib3.disable_warnings()

        self.url = f"https://{hostname}:{port}/webconsole/APIController"

        self.xml_login = f"""
            <Login> 
                <Username>{username}</Username>
                    <Password{" passwordform='encrypt'" if password_encrypted else ""}>{password}</Password>
            </Login>
        """

    def _send_xml_request(self, xmldata):
        headers = {"Accept": "application/xml"}
        response = requests.post(self.url, headers=headers, data={"reqxml": xmldata}, verify=self.certificate_verify, timeout=30)
        return response

    def _format_xml_response(self, response, entity_type):
        if "Status" in response["Response"]:
            status = response["Response"]["Status"]
            return {"data": [], "code": status["@code"], "text": status["#text"]}

        login = response["Response"]["Login"]
        if login["status"] == "Authentication Failure":
            return {"data": [], "code": "401", "text": login["status"]}

        if "Login" in response["Response"] and entity_type in response["Response"]:
            entity_type_response = response["Response"][entity_type]
            if "Status" in entity_type_response:
                status = entity_type_response["Status"]
                if "@code" in status:
                    return {"data": [], "code": status["@code"], "text": status["#text"]}
                elif "No. of records Zero." in status:
                    return {"data": [], "code": "526", "text": "Record does not exist."}

        entity_type_data = response["Response"][entity_type]
        response_data = [entity_type_data] if isinstance(entity_type_data, dict) else entity_type_data

        for item in response_data:
            item.pop("@transactionid", None)

        return {"data": response_data, "code": "216", "text": "Operation Successful."}

    # CREATE Entity_type
    def create(self, entity_type, entity_data):
        xml_action = f"""
            <Set  operation="add">
                    <{entity_type}>
                        {xmltodict.unparse(entity_data, full_document=False)}
                    </{entity_type}>
                </Set>
        """
        xml_request = f"<Request>{self.xml_login}{xml_action}</Request>"

        response = self._send_xml_request(xmldata=xml_request)
        return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)

    # READ Entity_type
    def read(self, entity_type, entity_data=None, filter_selector=LIKE):
        xml_action = f"""
            <Get>
                <{entity_type}>
                    {f'<Filter><key name="Name" criteria="{filter_selector}">{entity_data}</key></Filter>' if entity_data else ""}
                </{entity_type}>
            </Get>
        """
        xml_request = f"<Request>{self.xml_login}{xml_action}</Request>"

        response = self._send_xml_request(xmldata=xml_request)
        return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)

    # UPDATE Entity_type
    def update(self, entity_type, entity_data):
        xml_action = f"""
            <Set  operation="update">
                    <{entity_type}>
                        {xmltodict.unparse(entity_data, full_document=False)}
                    </{entity_type}>
            </Set>
        """
        xml_request = f"<Request>{self.xml_login}{xml_action}</Request>"

        response = self._send_xml_request(xmldata=xml_request)
        return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)

    # DELETE Entity_type
    def delete(self, entity_type, entity_data=None, filter_selector=EQ):
        if entity_type in ["FirewallRule"]:  # If the Filter is not applicable
            xml_action = f"""
                <Remove>
                    <{entity_type}>
                        <Name>{entity_data}</Name>
                    </{entity_type}>
                </Remove>
            """
        else:
            xml_action = f"""
                <Remove>
                    <{entity_type}>               
                        {f'<Filter><key name="Name" criteria="{filter_selector}">{entity_data}</key></Filter>' if entity_data else ""}
                    </{entity_type}>
                </Remove>
            """
        xml_request = f"<Request>{self.xml_login}{xml_action}</Request>"

        response = self._send_xml_request(xmldata=xml_request)
        return self._format_xml_response(xmltodict.parse(response.content.decode()), entity_type)
