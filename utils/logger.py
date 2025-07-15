from datetime import datetime

def log(text):
    now = datetime.now()
    timestamp = now.strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{timestamp} {text}")