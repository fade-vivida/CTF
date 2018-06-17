import flag

flag = flag.flag
sands = int(flag[5:-1].encode("hex"), 16)

holes = [257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373]

with open("sand.txt", "w") as f:
    for i in range(len(holes)):
        sand = sands % holes[i]
        f.write(str(sand)+"\n")
