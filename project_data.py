from typing import Tuple, Dict, Any


def get_all_data() -> Tuple[Dict[str, bool], Dict[str, str], Dict[str, Dict], Dict[str, Dict[str, Any]]]:
    users: Dict[str, bool] = {
        'auth0|6356ed1d5615e6a1bdb56435': False,
        'auth0|6356ed948d3ef662e0286c6d': False,
        'auth0|6356ee6ae584359a2df8303a': True
    }

    teams: Dict[str, str] = {
        'Dinamo': 'A',
        'Gorica': 'A',
        'Hajduk': 'A',
        'Istra 1961': 'A',
        'Lokomotiva': 'A',
        'Osijek': 'A',
        'Rijeka': 'A',
        'Slaven Belupo': 'A',
        'Šibenik': 'A',
        'Varaždin': 'A'
    }

    games: Dict[str, dict] = {
        '1': dict(
            team_a='Dinamo',
            team_b='Hajduk',
            team_a_score=1,
            team_b_score=0
        ),
        '2': dict(
            team_a='Slaven Belupo',
            team_b='Hajduk',
            team_a_score=1,
            team_b_score=2
        ),
        '3': dict(
            team_a='Dinamo',
            team_b='Šibenik',
            team_a_score=3,
            team_b_score=1
        ),
        '4': dict(
            team_a='Varaždin',
            team_b='Šibenik',
            team_a_score=1,
            team_b_score=1
        )
    }

    comments = {i: dict() for i in games}

    return users, teams, games, comments


def relu(x):
    if x < 0:
        return 0
    return x


def calculate_points(
        games: Dict[str, dict],
        teams: Dict[str, str]
) -> Dict[str, Dict[str, int]]:
    groups: Dict[str, Dict[str, int]] = {}

    for game in games.values():
        if teams[game['team_a']] not in groups:
            groups[teams[game['team_a']]] = {}

        if game['team_a'] not in groups[teams[game['team_a']]]:
            groups[teams[game['team_a']]][game['team_a']] = 0

        if game['team_b'] not in groups[teams[game['team_a']]]:
            groups[teams[game['team_a']]][game['team_b']] = 0

        if game['team_a_score'] == game['team_b_score']:
            groups[teams[game['team_a']]][game['team_a']] += 1
            groups[teams[game['team_a']]][game['team_b']] += 1
            continue

        groups[teams[game['team_a']]][game['team_a']] += relu(game['team_a_score'] - game['team_b_score'])
        groups[teams[game['team_a']]][game['team_b']] += relu(game['team_b_score'] - game['team_a_score'])

    return groups
