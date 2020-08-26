#!/usr/bin/env python
"""This script queries The Hive for SentinelOne generated cases older
than seven days, then checks if the resolved status is True in the
SentinelOne console. Finally it closes the associated case in TheHive

"""
import time
import re
import sys
import yaml
import datetime
import requests
from thehive4py.api import TheHiveApi
from thehive4py.query import And, Eq

# environment variables from config
with open("config.yml", "r") as f:
    cfg = yaml.load(f, Loader=yaml.FullLoader)
    S1API = cfg["sentinelone"]["apikey"]
    S1WEB = cfg["sentinelone"]["serverurl"]
    API = TheHiveApi((cfg["hive"]["serverurl"]), (cfg["hive"]["apikey"]))


def check_status(query):
    """Checks status of Hive Cases

    Queries for TheHive for SentinelOne generated cases older than seven days.
    Queries SentinelOne console to check threat_status resolution.
    """
    if query.status_code == 200:
        data = {}
        i, inc, cnt = 0, 0, 0
        while i < len(query.json()):
            check_date = datetime.date.today() - datetime.timedelta(days=7)
            if (query.json()[i]["createdAt"] / 1000) < time.mktime(check_date.timetuple()):
                tasks = API.get_case_tasks(query.json()[i]["id"])
                while inc < len(tasks.json()):
                    if (tasks.json()[inc]["status"] == ("Waiting")) or (tasks.json()[inc]["status"] == ("InProgress")):
                        cnt += 1
                    inc += 1
                match = re.search(r"\*\*id\*\*\s+(\S+)", query.json()[i]["description"])
                threat_status = requests.get(
                    str(S1WEB) + "/web/api/v2.0/threats/" + str(match.group(1)) + "/forensics?apiToken=" + str(S1API)
                )
                data[(i)] = {
                    "sirpId": query.json()[i]["id"],
                    "owner": query.json()[i]["owner"],
                    "createdAt": (
                        time.strftime("%m/%d/%Y %H:%M:%S", time.gmtime(query.json()[i]["createdAt"] / 1000.0))
                    ),
                    "totalTasks": len(tasks.json()),
                    "pendingTasks": cnt,
                    "sentinelId": match.group(1),
                    "SentinelResolved": threat_status.json()["data"]["result"]["resolved"],
                }
            i += 1
    else:
        print("fubard")
    update_sirp(data)


def update_sirp(data):
    """Auto Closes The Hive cases that meet criteria

    Posts case closure
    """
    i = 0
    while i < len(data):
        if data[i]["SentinelResolved"] is True:
            API.case.update(
                data[i]["sirpId"],
                status="Resolved",
                resolutionStatus="Other",
                summary="Resolved at Sentinel One Console, autoclosed",
                tags=["SentinelOne API"],
            )
        else:
            pass
        i += 1


RESPONSE = API.find_cases(query=And(Eq("status", "Open"), Eq("owner", "sentinelone")), range="all", sort=[])
check_status(RESPONSE)
sys.exit()
