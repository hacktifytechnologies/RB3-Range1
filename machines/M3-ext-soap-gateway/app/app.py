#!/usr/bin/env python3
"""
RPAL Pipeline Tariff SOAP Gateway — app.py
M3 · ext-soap-gateway · RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE

VULNERABILITY: XXE (XML External Entity) → SSRF → Cloud Instance Metadata Service

The SOAP XML parser has external entity processing enabled. This was a legacy
configuration from when DTD-based schema validation was used during development.
A forgetful developer never removed `resolve_entities=True` when moving to
production, and it was never caught in code review.

Attack path:
  1. Submit SOAP request with external entity referencing http://169.254.169.254/
  2. Server fetches the IMDS URL on behalf of the attacker (SSRF)
  3. IMDS returns IAM role credentials in the XML response body
  4. Credentials extracted from SOAP fault message (which includes entity content)

PNGRB (Petroleum and Natural Gas Regulatory Board) mandates third-party access
to RPAL's pipeline infrastructure — this SOAP service is the regulatory interface.
"""

from flask import Flask, request, make_response
from lxml import etree
import requests, logging, os, json, hashlib, datetime, re

app = Flask(__name__)
LOG_DIR = '/var/log/rpal/soap-gateway'
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(filename=f'{LOG_DIR}/gateway.log', level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s')

# Service account for the SOAP gateway (obtained from M2 batchQuery)
VALID_USER = 'rpal-tariff-svc'
VALID_PASS = 'TariffGW@Soap!2024#RPAL'

WSDL = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://rpal.in/tariff/v2"
             targetNamespace="http://rpal.in/tariff/v2"
             name="RPALTariffService">
  <types>
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="http://rpal.in/tariff/v2">
      <xs:element name="CalculateTariffRequest">
        <xs:complexType><xs:sequence>
          <xs:element name="pipelineSegment" type="xs:string"/>
          <xs:element name="volumeMscmd" type="xs:decimal"/>
          <xs:element name="gasType" type="xs:string"/>
          <xs:element name="contractorId" type="xs:string"/>
        </xs:sequence></xs:complexType>
      </xs:element>
      <xs:element name="CalculateTariffResponse">
        <xs:complexType><xs:sequence>
          <xs:element name="tariffRsPerMscmd" type="xs:decimal"/>
          <xs:element name="applicableFrom" type="xs:string"/>
          <xs:element name="regulatoryRef" type="xs:string"/>
        </xs:sequence></xs:complexType>
      </xs:element>
    </xs:schema>
  </types>
  <message name="CalculateTariffInput">
    <part name="parameters" element="tns:CalculateTariffRequest"/>
  </message>
  <message name="CalculateTariffOutput">
    <part name="parameters" element="tns:CalculateTariffResponse"/>
  </message>
  <portType name="RPALTariffPortType">
    <operation name="CalculateTariff">
      <input message="tns:CalculateTariffInput"/>
      <output message="tns:CalculateTariffOutput"/>
    </operation>
  </portType>
  <binding name="RPALTariffBinding" type="tns:RPALTariffPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="CalculateTariff">
      <soap:operation soapAction="http://rpal.in/tariff/v2/CalculateTariff"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
  </binding>
  <service name="RPALTariffService">
    <port name="RPALTariffPort" binding="tns:RPALTariffBinding">
      <soap:address location="http://tariff-gw.rpal.in:8080/TariffGateway"/>
    </port>
  </service>
</definitions>"""

TARIFF_TABLE = {
    'HVJ-DVPL': {'rate': 37.42, 'ref': 'PNGRB/T4S/HHPL/2024/01'},
    'DVPL-VDPL': {'rate': 29.18, 'ref': 'PNGRB/T4S/HHPL/2024/02'},
    'GREP-I':    {'rate': 44.67, 'ref': 'PNGRB/T4S/GREP/2023/08'},
    'DBPL':      {'rate': 52.33, 'ref': 'PNGRB/T4S/DBPL/2024/03'},
}

def soap_fault(code: str, message: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:{code}</faultcode>
      <faultstring>{message}</faultstring>
      <detail>
        <rpal:ErrorDetail xmlns:rpal="http://rpal.in/tariff/v2">
          <rpal:service>RPAL Pipeline Tariff Gateway v2.3</rpal:service>
          <rpal:timestamp>{datetime.datetime.utcnow().isoformat()}Z</rpal:timestamp>
        </rpal:ErrorDetail>
      </detail>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"""

def soap_response(tariff: float, pipeline: str, ref: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:tns="http://rpal.in/tariff/v2">
  <soap:Header>
    <tns:ResponseInfo>
      <tns:service>RPAL Pipeline Tariff Gateway</tns:service>
      <tns:version>2.3.0</tns:version>
      <tns:timestamp>{datetime.datetime.utcnow().isoformat()}Z</tns:timestamp>
    </tns:ResponseInfo>
  </soap:Header>
  <soap:Body>
    <tns:CalculateTariffResponse>
      <tns:tariffRsPerMscmd>{tariff}</tns:tariffRsPerMscmd>
      <tns:applicableFrom>2024-04-01</tns:applicableFrom>
      <tns:regulatoryRef>{ref}</tns:regulatoryRef>
      <tns:pipeline>{pipeline}</tns:pipeline>
      <tns:currency>INR</tns:currency>
      <tns:unit>Rs/MSCMD/100km</tns:unit>
    </tns:CalculateTariffResponse>
  </soap:Body>
</soap:Envelope>"""

@app.route('/TariffGateway/wsdl', methods=['GET'])
@app.route('/TariffGateway?wsdl', methods=['GET'])
def wsdl():
    return make_response(WSDL, 200, {'Content-Type': 'text/xml; charset=utf-8'})

@app.route('/')
@app.route('/TariffGateway')
def index():
    if 'wsdl' in request.args:
        return wsdl()
    return make_response("""<?xml version="1.0" encoding="UTF-8"?>
<html><body><h2>RPAL Pipeline Tariff SOAP Gateway</h2>
<p>Service endpoint: /TariffGateway</p>
<p>WSDL: <a href="/TariffGateway/wsdl">/TariffGateway/wsdl</a></p>
<p>Version: 2.3.0 | PNGRB Regulatory Interface</p>
</body></html>""", 200, {'Content-Type': 'text/html'})

@app.route('/TariffGateway', methods=['POST'])
def soap_endpoint():
    content_type = request.content_type or ''
    if 'xml' not in content_type and 'soap' not in content_type:
        return make_response(
            soap_fault('Client', 'Content-Type must be text/xml or application/soap+xml'),
            400, {'Content-Type': 'text/xml; charset=utf-8'}
        )

    body = request.get_data()
    if not body:
        return make_response(
            soap_fault('Client', 'Empty request body'),
            400, {'Content-Type': 'text/xml; charset=utf-8'}
        )

    logging.info(f"SOAP_REQUEST size={len(body)} ip={request.remote_addr} "
                 f"action={request.headers.get('SOAPAction','')}")

    try:
        # VULNERABILITY: resolve_entities=True allows XXE
        # The parser will fetch external entities declared in DOCTYPE
        # An attacker can point an external entity to:
        #   http://169.254.169.254/latest/meta-data/
        # The server fetches it and includes the content in error/response XML
        parser = etree.XMLParser(
            resolve_entities=True,       # << VULNERABILITY: resolves external entities
            no_network=False,            # << VULNERABILITY: allows network access
            load_dtd=True,               # << VULNERABILITY: loads external DTDs
            huge_tree=True
        )
        try:
            root = etree.fromstring(body, parser=parser)
        except etree.XMLSyntaxError as e:
            # If the XML contains entity references that resolve to content,
            # lxml may include that content in the error message or parsed tree
            err_str = str(e)
            logging.warning(f"XML_PARSE_ERROR: {err_str[:500]} ip={request.remote_addr}")
            return make_response(
                soap_fault('Client', f'XML parse error: {err_str}'),
                400, {'Content-Type': 'text/xml; charset=utf-8'}
            )

        # Extract resolved entity values from the XML tree
        # (This is where SSRF content appears in XXE attacks)
        xml_text = etree.tostring(root, encoding='unicode')

        # Check WS-Security credentials
        ns = {'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
              'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
              'tns':  'http://rpal.in/tariff/v2'}

        username_el = root.find('.//wsse:UsernameToken/wsse:Username', ns)
        password_el = root.find('.//wsse:UsernameToken/wsse:Password', ns)

        if username_el is None or password_el is None:
            return make_response(
                soap_fault('Client.Security', 'WS-Security UsernameToken required'),
                401, {'Content-Type': 'text/xml; charset=utf-8',
                      'WWW-Authenticate': 'WS-Security realm="RPAL Tariff Gateway"'}
            )

        username = (username_el.text or '').strip()
        password = (password_el.text or '').strip()

        if username != VALID_USER or password != VALID_PASS:
            logging.warning(f"AUTH_FAIL user={username} ip={request.remote_addr}")
            return make_response(
                soap_fault('Client.Security', 'Authentication failed — invalid credentials'),
                401, {'Content-Type': 'text/xml; charset=utf-8'}
            )

        logging.info(f"AUTH_OK user={username} ip={request.remote_addr}")

        # Process tariff calculation
        pipeline_el = root.find('.//tns:pipelineSegment', ns)
        volume_el   = root.find('.//tns:volumeMscmd', ns)

        if pipeline_el is None:
            # If the pipeline segment element contains resolved XXE content,
            # include it in the response — this is how the SSRF output leaks
            pipeline_text = ''
            # Check if any resolved entity content ended up in the XML
            if '169.254.169.254' in xml_text or 'AccessKeyId' in xml_text:
                logging.critical(
                    f"XXE_SSRF_DETECTED IMDS_ACCESS ip={request.remote_addr} "
                    f"content_preview={xml_text[:200]}"
                )
            return make_response(
                soap_fault('Client', f'Missing pipelineSegment element. '
                           f'Parsed XML content: {xml_text[:1000]}'),
                400, {'Content-Type': 'text/xml; charset=utf-8'}
            )

        pipeline = (pipeline_el.text or '').strip()
        volume   = float(volume_el.text) if volume_el is not None else 0.0

        if pipeline not in TARIFF_TABLE:
            available = ', '.join(TARIFF_TABLE.keys())
            return make_response(
                soap_fault('Client',
                    f'Unknown pipeline segment: {pipeline}. '
                    f'Available: {available}'),
                400, {'Content-Type': 'text/xml; charset=utf-8'}
            )

        tariff_info = TARIFF_TABLE[pipeline]
        tariff = round(tariff_info['rate'] * (volume / 100), 4)

        return make_response(
            soap_response(tariff, pipeline, tariff_info['ref']),
            200, {'Content-Type': 'text/xml; charset=utf-8',
                  'SOAPAction': 'http://rpal.in/tariff/v2/CalculateTariffResponse'}
        )

    except Exception as e:
        logging.error(f"SOAP_ERROR: {e} ip={request.remote_addr}")
        return make_response(
            soap_fault('Server', f'Internal gateway error: {str(e)}'),
            500, {'Content-Type': 'text/xml; charset=utf-8'}
        )

# ── Mock IMDS endpoint ─────────────────────────────────────────────────────────
# Simulates the AWS/OpenStack instance metadata service at 169.254.169.254.
# In a real OpenStack deployment this would be on the actual link-local address.
# For the exercise, it runs on localhost and the XXE SSRF is directed here.
# The setup.sh adds an iptables DNAT rule: 169.254.169.254:80 → 127.0.0.1:8080/imds/

@app.route('/imds/')
@app.route('/imds/latest/')
@app.route('/imds/latest/meta-data/')
def imds_root():
    return make_response("""ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
reservation-id
security-groups
services/""", 200, {'Content-Type': 'text/plain'})

@app.route('/imds/latest/meta-data/iam/')
def imds_iam():
    return make_response("info\nsecurity-credentials/\n", 200, {'Content-Type': 'text/plain'})

@app.route('/imds/latest/meta-data/iam/security-credentials/')
def imds_iam_creds_list():
    return make_response("rpal-upstream-api-role\n", 200, {'Content-Type': 'text/plain'})

@app.route('/imds/latest/meta-data/iam/security-credentials/rpal-upstream-api-role')
def imds_iam_creds():
    """
    The IAM role credentials returned by the IMDS.
    These credentials are valid for the internal API gateway at 203.x.x.x:8000.
    This is what the attacker extracts via XXE → SSRF → IMDS.
    """
    now = datetime.datetime.utcnow()
    # Deterministic credentials — seeded from date so scoring is consistent
    seed = f"RPAL-IMDS-CREDS-{now.strftime('%Y-%m-%d')}"
    import hashlib
    key_id_raw = hashlib.sha256(f"{seed}:keyid".encode()).hexdigest()[:20].upper()
    secret_raw = hashlib.sha256(f"{seed}:secret".encode()).hexdigest()[:40]
    token_raw  = hashlib.sha256(f"{seed}:token".encode()).hexdigest()

    return make_response(json.dumps({
        "Code":            "Success",
        "LastUpdated":     now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Type":            "AWS-HMAC",
        "AccessKeyId":     f"ASIA{key_id_raw}",
        "SecretAccessKey": secret_raw,
        "Token":           token_raw * 2,
        "Expiration":      (now + datetime.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_rpal_note":      "rpal-upstream-api-role — grants access to internal API gateway",
        "_rpal_endpoint":  "http://203.x.x.x:8000/api/v2/admin/export",
    }, indent=2), 200, {'Content-Type': 'application/json'})

@app.route('/imds/latest/meta-data/instance-id')
def imds_instance_id():
    return make_response("i-rpal-soap-gw-001\n", 200, {'Content-Type': 'text/plain'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
