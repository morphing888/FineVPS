# Создаёт правдоподобную историю, чтобы проверить длинные графики.
import json, math, random, sys, time
path, user = sys.argv[1], sys.argv[2]
now = int(time.time())
def wave(t, base):
    day = 0.55 + 0.45 * math.sin((t % 86400) / 86400 * 2 * math.pi - 1.4)
    return base * day * random.uniform(0.75, 1.25)
def bucket(t, sec, gap=False):
    d = wave(t, 900000) * sec
    u = d * 0.12
    via, direct = d * 0.72, d * 0.28
    s2 = 0 if gap else sec
    return {"t": t, "s": sec, "s2": s2, "v": [int(d), int(d + u), 0 if gap else int(via), 0 if gap else int(via), int(via), int(direct)]}
minute = [bucket(now - now % 60 - i * 60, 60, 2500 < i < 2560) for i in range(2880, 0, -1)]
hour = [bucket(now - now % 3600 - i * 3600, 3600, 300 < i < 309) for i in range(24 * 40, 0, -1)]
days, users = {}, {}
for b in hour:
    k = time.strftime("%Y-%m-%d", time.gmtime(b["t"] + 3 * 3600))
    days.setdefault(k, [0] * 6)
    days[k] = [a + c for a, c in zip(days[k], b["v"])]
    users.setdefault(k, [0, 0])
    users[k][0] += b["v"][1] // 8
    users[k][1] += b["v"][0] // 8
json.dump({"minute": minute, "hour": hour, "days": days, "userDays": {user: users}}, open(path, "w"))
