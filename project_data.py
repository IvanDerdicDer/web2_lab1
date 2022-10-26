from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from typing import List, Tuple, Dict, Optional


@dataclass_json()
@dataclass()
class Game:
    team_a: str
    team_b: str
    team_a_score: int = field(default=0)
    team_b_score: int = field(default=0)


def get_all_data() -> Tuple[Dict[str, bool], Dict[str, str], Dict[str, Game]]:
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

    games: Dict[str, Game] = {
        '1': Game(
            'Dinamo',
            'Hajduk',
            1,
            0
        ),
        '2': Game(
            'Slaven Belupo',
            'Hajduk',
            1,
            2
        ),
        '3': Game(
            'Dinamo',
            'Šibenik',
            3,
            1
        ),
        '4': Game(
            'Varaždin',
            'Šibenik',
            1,
            1
        )
    }

    return users, teams, games


def relu(x):
    if x < 0:
        return 0
    return x


def calculate_points(
        games: Dict[str, Game],
        teams: Dict[str, str]
) -> Dict[str, Dict[str, int]]:
    groups: Dict[str, Dict[str, int]] = {}

    for game in games.values():
        if teams[game.team_a] not in groups:
            groups[teams[game.team_a]] = {}

        if game.team_a not in groups[teams[game.team_a]]:
            groups[teams[game.team_a]][game.team_a] = 0

        if game.team_b not in groups[teams[game.team_a]]:
            groups[teams[game.team_a]][game.team_b] = 0

        if game.team_a_score == game.team_b_score:
            groups[teams[game.team_a]][game.team_a] += 1
            groups[teams[game.team_a]][game.team_b] += 1
            continue

        groups[teams[game.team_a]][game.team_a] += relu(game.team_a_score - game.team_b_score)
        groups[teams[game.team_a]][game.team_b] += relu(game.team_b_score - game.team_a_score)

    return groups
