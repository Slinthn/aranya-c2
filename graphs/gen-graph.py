# FYP graph for poster
import matplotlib
import matplotlib.pyplot as plt
 
y = [
    0.41715,
    1776407596.453605465 - 1776407595.172755964,
    2.516203,
    1776407695.994606107 - 1776407691.417134841,
    1776408606.655358381 - 1776408591.832879444,
    1776407833.322588668 - 1776407808.487957641,
    # 1776408180.776403477 - 1776408156.836206305
]

x = [
    10,
    50,
    100,
    150,
    350,
    500,
    # 627
]

matplotlib.rcParams.update({'font.size': 36})

p = plt.figure(figsize=(19.20,19.20))
plt.title("Time taken for command to propagate vs.\nNumber of peers in network")
plt.xlabel("Number of nodes\nin infected network")
plt.ylabel("Command propogation time (s)")
plt.grid()
plt.plot(x, y, linewidth=9.0)

p.savefig("figure.png")
