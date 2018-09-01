require("bit")
borad = {
  {
    1,
    2,
    3
  },
  {
    4,
    5,
    6
  },
  {
    7,
    8,
    0
  }
}
sx = 3
sy = 3
function swap_chess(x, y, xx, yy)
  local t = borad[x][y]
  borad[x][y] = borad[xx][yy]
  borad[xx][yy] = t
end
function move_chess(d)
  if d == "S" and sx == 1 or d == "W" and sx == 3 or d == "D" and sy == 1 or d =
= "A" and sy == 3 then
    return
  end
  if d == "S" then
    swap_chess(sx, sy, sx - 1, sy)
    sx = sx - 1
  elseif d == "W" then
    swap_chess(sx, sy, sx + 1, sy)
    sx = sx + 1
  elseif d == "D" then
    swap_chess(sx, sy, sx, sy - 1)
    sy = sy - 1
  elseif d == "A" then
    swap_chess(sx, sy, sx, sy + 1)
    sy = sy + 1
  end
end
function randomize()
  local d = {
    "W",
    "S",
    "A",
    "D"
  }
  math.randomseed(os.time())
  for i = 1, 1000 do
    move_chess(d[math.random(4)])
  end
end
function display()
  local s = ""
  for x = 1, 3 do
    for y = 1, 3 do
      s = s .. "| " .. borad[x][y] .. " "
    end
    s = s .. "|\n"
    if x ~= 3 then
      s = s .. "-------------\n"
    end
  end
  s = s .. "\n"
  io.write(s)
end
secret = {
  171,
  201,
  244,
  200,
  118,
  100,
  138,
  190,
  170,
  159,
  94,
  91,
  42,
  184,
  8,
  98,
  198,
  134,
  110,
  165,
  108,
  219,
  117,
  179,
  180,
  179,
  221,
  144,
  167,
  155
}
print("i want to play a game with u")
io.read()
print("finish this game 10000000 times and i'll show u the flag, trust me")
print("use WSAD/wsad to move, ctrl+z to quit")
io.read()
times = 0
total = 10000000
while times < total do
  randomize()
  f = false
  os.execute("cls")
  print("times: " .. times .. "/" .. total)
  display()
  repeat
    io.write("> ")
    s = io.read()
    if s == nil then
      break
    end
    for i = 1, string.len(s) do
      move_chess(string.upper(string.sub(s, i, i)))
    end
    os.execute("cls")
    print("times: " .. times .. "/" .. total)
    display()
    f = true
    for i = 0, 7 do
      if borad[math.floor(i / 3) + 1][i % 3 + 1] ~= i + 1 then
        f = false
        break
      end
    end
    f = f and borad[3][3] == 0
  until f
  if f then
    times = times + 1
    math.randomseed(times)
    for i = 1, #secret do
      secret[i] = bit.bxor(secret[i], math.random(255))
    end
  else
    os.execute("cls")
    break
  end
end
if times == total then
  os.execute("cls")
  print("congrats!")
  flag = ""
  for i, v in ipairs(secret) do
    flag = flag .. string.char(v)
  end
  print(flag)
end
