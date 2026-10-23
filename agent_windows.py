import requests
import time
import os

try:
    import win32evtlog
except ModuleNotFoundError:
    win32evtlog = None


# ============================================================
# CONFIG
# ============================================================

SERVER = "http://127.0.0.1:5001/ingest"


# ============================================================
# SEND LOG
# ============================================================

def send_log(log):

    try:

        response = requests.post(

            SERVER,

            json={
                "log": log
            },

            headers={
                "X-Agent-Token": os.environ["AGENT_API_TOKEN"]
            },

            timeout=3

        )
        response.raise_for_status()

        print(
            "[SENT]",
            log,
            "| HTTP",
            response.status_code
        )

    except Exception as e:

        print(
            "[ERROR]",
            e
        )


# ============================================================
# WINDOWS EVENT LOG
# ============================================================

def read_windows_logs():
    if win32evtlog is None:
        raise RuntimeError("win32evtlog is required to read Windows system logs")

    server = "localhost"

    log_type = "System"


    try:

        hand = win32evtlog.OpenEventLog(

            server,

            log_type

        )

    except Exception as e:

        print(
            "[CRITICAL ERROR] "
            "Failed to open Windows log:",
            e
        )

        return


    flags = (

        win32evtlog.EVENTLOG_BACKWARDS_READ

        |

        win32evtlog.EVENTLOG_SEQUENTIAL_READ

    )


    print(
        f"🔬 Actively tailing "
        f"Windows [{log_type}] events..."
    )

    seen_event_ids = set()


    # ========================================================
    # INITIAL CONNECTION TEST
    # ========================================================

    send_log(
        "WINDOWS_AGENT_ONLINE|admin|127.0.0.1"
    )


    while True:

        try:

            events = win32evtlog.ReadEventLog(

                hand,

                flags,

                0

            )


            if events:

                for event in events:

                    if event.RecordNumber in seen_event_ids:

                        continue

                    seen_event_ids.add(event.RecordNumber)

                    event_id = event.EventID


                    # ==================================================
                    # SYSTEM EVENTS
                    # ==================================================

                    if event_id in [

                        7036,

                        1074,

                        6005,

                        6006

                    ]:

                        log = (
                            "LOGIN_SUCCESS"
                            "|admin"
                            "|127.0.0.1"
                        )

                        send_log(
                            log
                        )


                    # ==================================================
                    # ERROR EVENTS
                    # ==================================================

                    elif (

                        event.EventType
                        ==
                        win32evtlog.EVENTLOG_ERROR_TYPE

                    ):

                        log = (
                            "LOGIN_FAIL"
                            "|user"
                            "|127.0.0.1"
                        )

                        send_log(
                            log
                        )


        except Exception as e:

            print(
                "[WINDOWS EVENT ERROR]",
                e
            )


        time.sleep(5)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 50)
    print("       🪟 WINDOWS SECURITY AGENT")
    print("=" * 50)
    print()
    print(
        "Server:",
        SERVER
    )
    print()
    print(
        "🚀 Windows Agent Started..."
    )
    print()

    read_windows_logs()