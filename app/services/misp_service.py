import requests
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _headers(key):
    return {'Authorization': key, 'Accept': 'application/json', 'Content-Type': 'application/json'}


def check_misp_connection(url, key):
    try:
        r = requests.get(f'{url}/users/view/me', headers=_headers(key), verify=False, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def get_misp_summary(apt_id, apt_name, url, key):
    summary = {'available': False, 'event_count': 0, 'attribute_count': 0,
                'event_links': [], 'has_galaxy_data': False, 'error': None}
    try:
        if not check_misp_connection(url, key):
            summary['error'] = 'MISP unreachable or auth failed'
            return summary
        summary['available'] = True
        r = requests.post(f'{url}/events/restSearch', headers=_headers(key),
                          json={'returnFormat': 'json', 'tags': [apt_name], 'limit': 10},
                          verify=False, timeout=5)
        if r.status_code == 200:
            events = r.json().get('response', [])
            summary['event_count'] = len(events)
            for e in events[:5]:
                ev = e.get('Event', {})
                eid = ev.get('id')
                if eid:
                    summary['event_links'].append({
                        'id': eid, 'title': ev.get('info', 'Unnamed')[:80],
                        'url': f'{url}/events/view/{eid}'
                    })
        r2 = requests.post(f'{url}/attributes/restSearch', headers=_headers(key),
                           json={'returnFormat': 'json', 'tags': [apt_name], 'limit': 50},
                           verify=False, timeout=5)
        if r2.status_code == 200:
            summary['attribute_count'] = len(r2.json().get('response', {}).get('Attribute', []))
    except Exception as e:
        summary['error'] = str(e)
    return summary
