import matplotlib
import matplotlib.pyplot as plt
#plt.style.use('seaborn-whitegrid')
import numpy as np
#from scipy.interpolate import make_interp_spline, BSpline

#matplotlib.rcParams['font.family'] = "sans-serif"
plt.rcParams["font.family"] = "Times New Roman"
matplotlib.font_manager._rebuild()


fig = plt.figure()
ax = plt.axes()


fig = plt.gcf()
fig.set_size_inches(10, 6)
fig.subplots_adjust(bottom=0.18)

plt.rcParams.update({'font.size': 20})


#plt.rc('xtick',labelsize=20)
#plt.rc('ytick',labelsize=20)

#plt.rcParams['xtick.labelsize']=20
#plt.rcParams['ytick.labelsize']=20

ax.tick_params(labelsize=20)

plt.margins(0.03)

#x_ticks=['0','2','4', '6', '8', '10', '12', '14', '16']
#ax.set_xticklabels(np.arange(0, 17.5, step=0.5), rotation=0, fontsize=20)
#plt.xticks(np.arange(0, 17.5, step=1.0))

#y_ticks=['y tick 1','y tick 2','y tick 3']
#ax.set_yticklabels(y_ticks, rotation=0, fontsize=8)
#plt.yticks(np.arange(0, 20, step=2.5))

program_names = ["hiawatha", "httpd", "lighttpd", "mupdf", "nginx", "openssl", "proftpd", "sqlite3", "openssh", "thttpd", "tor"]

A = np.array([10,23,6,19,10,19,23,19,19,17,18])
B = np.array([0,1,0,2,0,2,1,2,0,2,1])
C = np.array([1,1,0,0,0,0,0,0,13,0,1])
X = np.arange(len(A))

#N = 8
#A = np.random.random(N)
#B = np.random.random(N)
#C = np.random.random(N)
#X = np.arange(N)
plt.bar(X, A, color = 'w', hatch = ' ', label='stack')
plt.bar(X, B, bottom = A, color = 'w', hatch = 'x', label='heap')
plt.bar(X, C, bottom = A+B, color = 'w', hatch = '.', label='ds')


plt.xticks(X, program_names, rotation=30)

#plt.legend()

#ax.legend()

plt.legend(frameon=False, prop={'size': 20}, columnspacing=0.5, handletextpad=0.5, bbox_to_anchor=(1.02,1.03))

#plt.xlabel('time (second)', fontsize=24)
plt.ylabel('Number of unique libc pointers', fontsize=20)
#ax.yaxis.set_label_coords(0, 0) 

#plt.show()

fig.savefig('libc-pointers.png', dpi=400)
