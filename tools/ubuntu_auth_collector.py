import re
import time
import requests



from datetime import datetime, timezone


SOC_URL = "http://192.168.72.1:8000/api/events/live"

AUTH_LOG = "/var/log/auth.log"


failed_pattern = re.compile(


    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)




def send_event(event):

    try:
        response = requests.post(
            SOC_URL,
            json={
                "dataset": "real",
                "event": event
            },
            timeout=5
        )

        print(
            response.status_code,
            response.text
        )

    except Exception as e:
        print(
            "SOC connection failed:",
            e
        )

def parse_line(line):
    match = failed_pattern.search(line)
    if not match:
        return None

    user = match.group(1)
    source_ip = match.group(2)

    # Preserve the original timestamp from Ubuntu auth.log.
    timestamp_match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\S+)",
        line
    )

    if timestamp_match:
        timestamp = datetime.fromisoformat(
            timestamp_match.group(1)
        ).astimezone(timezone.utc).isoformat()
    else:
        timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "timestamp": timestamp,
        "event_type": "authentication",
        "user": user,
        "host": "ubuntu",
        "source_ip": source_ip,
        "destination_ip": "192.168.72.131",
        "port": 22,
        "protocol": "SSH",
        "status": "failed",
        "authentication_result": "failure",
        "raw_event": line.strip()
    }
def follow():

    with open(
        AUTH_LOG,
        "r"
    ) as file:

        file.seek(0,2)


        while True:

            line = file.readline()


            if not line:
                time.sleep(1)
                continue


            event = parse_line(line)


            if event:

                print(
                    "\nDetected:",
                    event
                )

                send_event(event)



if __name__ == "__main__":

    print(
        "Ubuntu Auth Log Collector Started"
    )

    follow()