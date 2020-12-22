import ssl
import json
import base64
import syslog
import traceback
from pyovpn.plugin import (SUCCEED, FAIL)

try:
    import httplib
except ImportError:
    import http.client as httplib

try:
    from urllib import quote, urlencode
except ImportError:
    from urllib.parse import quote, urlencode

SYNCHRONOUS = False

# --------------------------------------
# Please provide your credentials:
NAS_IDENTIFIER = ''
SHARED_SECRET = ''
HOST = 'api.multifactor.ru'
# --------------------------------------

API_STATUS_GRANTED = 'Granted'
API_STATUS_DENIED = 'Denied'
API_STATUS_AWAITING = 'AwaitingAuthentication'

CHALLENGE_MSG = 'Please enter Multifactor passcode:'
IS_FAILED_MSG = 'Communication with Multifactor failed.'

def log(msg):
    msg = 'Multifactor OpenVPN AS: {}'.format(msg)
    syslog.syslog(msg)

def call(method, path, **kwargs):
    basic_auth = base64.b64encode('{}:{}'.format(NAS_IDENTIFIER, SHARED_SECRET))

    headers = {
        'Authorization': 'Basic {}'.format(basic_auth),
        'Content-Type': 'application/json'
    }

    body = json.dumps(kwargs)
    uri = path

    conn = httplib.HTTPSConnection(HOST, 443)
    conn.request(method, uri, body, headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()

    return response.status, response.reason, data

def api(method, path, **kwargs):
    status, reason, data = call(method, path, **kwargs)
    if status != 200:
        raise RuntimeError('Received {} {}: {}'.format(status, reason, data))

    try:
        data = json.loads(data)
        log("API response received {}".format(data))
        return data
    except (ValueError, KeyError) as e:
        raise RuntimeError('Bad API response: {}; Error stack trace: {}'.format(data, e))

def challenge_request(username, ipaddr):
    log('challenge requested for {}'.format(username))

    args = {
        'Identity': username,
        'Ip': ipaddr
    }

    response = api('POST', '/access/requests/ra', **args)
    request_id = response['model']['id']
    status = response['model']['status']

    if not status:
        log('API error: {}'.format(response))
        raise RuntimeError('API error: {}'.format(response))

    if status == API_STATUS_AWAITING:
        log('challenge request for {} issued: {}'.format(username, status))
    elif status == API_STATUS_DENIED:
        log('challenge request failure for {}: {}'.format(username, status))
    elif status == API_STATUS_GRANTED:
        log('challenge request success for {}: {}'.format(username, status))
    else:
        log('unknown challenge request status: {}'.format(status))

    return request_id, status

def auth(username, password, prev_id):
    log('authenticating {}'.format(username))

    args = {
        'Identity': username,
        'Challenge': password,
        'RequestId': prev_id
    }

    response = api('POST', '/access/requests/ra/challenge', **args)
    status = response['model']['status']

    if not status:
        log('API error: {}'.format(response))
        status = "API error"
        raise RuntimeError('API error: {}'.format(response))

    if status == API_STATUS_GRANTED:
        log('auth success for {}: {}'.format(username, status))
    elif status == API_STATUS_DENIED:
        log('auth failure for {}: {}'.format(username, status))
    elif status == API_STATUS_AWAITING:
        log('auth challenge input for {}: {}'.format(username, status))
    else:
        log('unknown auth status for {}: {}'.format(username, status))

    return status

def post_auth_cr(authcred, attributes, authret, info, crstate):
    log('auth_method: {}'.format(info.get('auth_method')))
    if info.get('auth_method') in ('session', 'autologin'):
        return authret

    username = authcred['username']
    ipaddr = authcred['client_ip_addr']

    if crstate.get('challenge'):
        challenge_response = crstate.response()
        crstate['retry_id'] += 1
        log('retry id for {}: {}'.format(username, crstate.get('retry_id')))
        try:
            prev_id = crstate.get('prev_id')
            status = auth(username, challenge_response, prev_id)
            if status == API_STATUS_GRANTED:
                crstate.expire()
                authret['status'] = SUCCEED
                authret['reason'] = "Multifactor authentication success."
            elif status == API_STATUS_AWAITING:
                retry_id = crstate.get('retry_id')
                if crstate.get('retry_id') > 0:
                  crstate.challenge_post_auth(authret, "Incorrect passcode. Retry {}/3:".format(retry_id+1), echo=True)
            else:
              authret['status'] = FAIL
              authret['reason'] = "Multifactor authentication failed."
              authret['client_reason'] = authret['reason']
        except Exception as e:
            log(traceback.format_exc())
            authret['status'] = FAIL
            authret['reason'] = "Unhandled exception in auth: {}".format(e)
            authret['client_reason'] = IS_FAILED_MSG
    else:
        try:
            prev_id, status = challenge_request(username, ipaddr)
            crstate['prev_id'] = prev_id
            if status == API_STATUS_AWAITING:
                crstate['challenge'] = True
                crstate['retry_id'] = 0
                crstate.challenge_post_auth(authret, CHALLENGE_MSG, echo=True)
            elif status != API_STATUS_GRANTED:
                authret['status'] = FAIL
                authret['reason'] = status
                authret['client_reason'] = authret['reason']
        except Exception as e:
            log(traceback.format_exc())
            authret['status'] = FAIL
            authret['reason'] = "Unhandled exception in challenge request: {}".format(e)
            authret['client_reason'] = IS_FAILED_MSG

    return authret