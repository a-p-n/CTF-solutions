from datetime import datetime, timedelta
f1 = open('1.txt', 'rb').read()

target = datetime.strptime("12:38:13", "%H:%M:%S")
start = target - timedelta(seconds=20)

current = start
while current < target:
    c = (current.strftime("%H:%M:%S"))
    current += timedelta(seconds=1)
