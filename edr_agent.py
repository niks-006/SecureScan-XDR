import os
import time
import requests
import threading

try:
    import psutil
except ModuleNotFoundError:
    psutil = None

try:
    import yara
except ModuleNotFoundError:
    yara = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ModuleNotFoundError:
    Observer = None
    FileSystemEventHandler = object


# ============================================================
# CONFIG
# ============================================================

SERVER = "http://127.0.0.1:5001/ingest"

ENABLE_ATTACK_SIMULATION = False

try:

    USERNAME = os.getlogin()

except Exception:

    USERNAME = os.environ.get(
        "USERNAME",
        "unknown"
    )

IP = "127.0.0.1"


# ============================================================
# YARA RULES
# ============================================================

RULES = (
    yara.compile(
        source="""

        rule SuspiciousFile

        {

            strings:

                $a = "malware"
                $b = "trojan"
                $c = "ransomware"
                $d = "keylogger"

            condition:

                any of them

        }

        """
    )
    if yara is not None
    else None
)


# ============================================================
# SEND LOG
# ============================================================

def send_log(event):

    log = (
        f"{event}|{USERNAME}|{IP}"
    )

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
            f"[SENT] {log} "
            f"| HTTP {response.status_code}"
        )

    except Exception as e:

        print(
            f"[ERROR] Cannot send log: {e}"
        )


# ============================================================
# PROCESS MONITOR
# ============================================================

def monitor_processes():

    suspicious_keywords = [

        "powershell",

        "mimikatz",

        "nmap",

        "hydra",

        "metasploit",

        "keylogger"

    ]

    already_detected = set()

    while True:

        try:

            for proc in psutil.process_iter(
                ["name"]
            ):

                try:

                    name = proc.info["name"]

                    if not name:

                        continue

                    lower = name.lower()

                    for keyword in suspicious_keywords:

                        if keyword in lower:

                            unique =name

                            if (
                                unique
                                not in
                                already_detected
                            ):

                                already_detected.add(
                                    unique
                                )

                                print(
                                    "[ALERT] "
                                    "Suspicious Process:",
                                    name
                                )

                                send_log(
                                    "SUSPICIOUS"
                                )

                except Exception:

                    pass

            time.sleep(5)

        except Exception as e:

            print(
                "[PROCESS MONITOR ERROR]",
                e
            )


# ============================================================
# FILE WATCHER
# ============================================================

encrypted_counter = 0


class Watcher(
    FileSystemEventHandler
):


    def process_file(self, path):

        global encrypted_counter

        path = path.lower()


        ignored = [

            "siem_logs.db",

            "siem_logs.db-journal",

            ".tmp"

        ]


        for item in ignored:

            if item in path:

                return


        print(
            f"[FILE EVENT] {path}"
        )


        # ====================================================
        # FILE CREATED
        # ====================================================

        send_log(
            "FILE_CREATED"
        )


        # ====================================================
        # RANSOMWARE
        # ====================================================

        suspicious_extensions = [

            ".encrypted",

            ".locked",

            ".crypt",

            ".enc"

        ]


        for ext in suspicious_extensions:

            if path.endswith(ext):

                encrypted_counter += 1

                print(
                    "[RANSOMWARE DETECTED]",
                    path
                )

                send_log(
                    "RANSOMWARE"
                )


                if encrypted_counter >= 2:

                    print(
                        "[CRITICAL] "
                        "Multiple encrypted "
                        "files detected"
                    )

                    send_log(
                        "CRITICAL"
                    )


        # ====================================================
        # YARA
        # ====================================================

        try:

            if os.path.isfile(path):

                time.sleep(1)

                matches = RULES.match(path)

                if matches:

                    print(
                        "[YARA MATCH]",
                        path
                    )

                    send_log(
                        "YARA_MATCH"
                    )

        except Exception as e:

            print(
                "[YARA ERROR]",
                e
            )


    def on_created(
        self,
        event
    ):

        if not event.is_directory:

            self.process_file(
                event.src_path
            )


    def on_modified(
        self,
        event
    ):

        if not event.is_directory:

            self.process_file(
                event.src_path
            )


# ============================================================
# FILE MONITOR
# ============================================================

def monitor_files():

    possible_paths = [

        os.path.join(
            os.path.expanduser("~"),
            "Desktop"
        ),

        os.path.join(
            os.path.expanduser("~"),
            "OneDrive",
            "Desktop"
        )

    ]


    watch_path = None


    for path in possible_paths:

        print(
            f"[CHECKING PATH] {path}"
        )

        if os.path.exists(path):

            watch_path = path

            break


    if not watch_path:

        print(
            "[ERROR] Desktop not found"
        )

        return


    print(
        f"[WATCHING] {watch_path}"
    )


    observer = Observer()


    observer.schedule(

        Watcher(),

        watch_path,

        recursive=True

    )


    observer.start()


    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()


    observer.join()


# ============================================================
# LOGIN SIMULATION
# ============================================================

def simulate_attacks():

    while True:

        time.sleep(20)

        print(
            "[SIMULATION] "
            "Failed Login Event"
        )

        send_log(
            "LOGIN_FAIL"
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 50)
    print("       🛡 EDR AGENT")
    print("=" * 50)
    print()
    print(
        "Server:",
        SERVER
    )
    print(
        "User:",
        USERNAME
    )
    print(
        "IP:",
        IP
    )
    print()
    print("🚀 EDR Agent Running...")
    print()
    print("=" * 50)
    print()


    # Immediate connectivity test

    send_log(
        "EDR_AGENT_ONLINE"
    )


    threading.Thread(

        target=monitor_processes,

        daemon=True

    ).start()


    threading.Thread(

        target=monitor_files,

        daemon=True

    ).start()


    if ENABLE_ATTACK_SIMULATION:

        threading.Thread(

            target=simulate_attacks,

            daemon=True

        ).start()


    while True:

        time.sleep(1)