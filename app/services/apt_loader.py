import json
import os

PROFILES_DIR = os.path.join(os.path.dirname(__file__), '../../data/apt_profiles')


def load_profile(apt_id: str) -> dict:
    path = os.path.join(PROFILES_DIR, f'{apt_id}.json')
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def list_profiles() -> list:
    profiles = []
    for fname in sorted(os.listdir(PROFILES_DIR)):
        if fname.endswith('.json'):
            apt_id = fname.replace('.json', '')
            profile = load_profile(apt_id)
            if profile:
                profiles.append({
                    'id': profile['id'],
                    'display_name': profile['display_name'],
                    'attribution': profile['attribution'],
                    'motivation': profile['motivation'],
                    'primary_environment': profile['primary_environment'],
                    'description': profile['description']
                })
    return profiles
