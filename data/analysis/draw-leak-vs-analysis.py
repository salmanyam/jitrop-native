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
#fig.set_size_inches(6, 4)
#fig.subplots_adjust(bottom=0.18)

plt.rcParams.update({'font.size': 20})


#plt.rc('xtick',labelsize=20)
#plt.rc('ytick',labelsize=20)

#plt.rcParams['xtick.labelsize']=20
#plt.rcParams['ytick.labelsize']=20

ax.tick_params(labelsize=20)

#ax.margins(0.10, 0.20)  

#x_ticks=['0','2','4', '6', '8', '10', '12', '14', '16']
#ax.set_xticklabels(np.arange(0, 17.5, step=0.5), rotation=0, fontsize=20)
#plt.xticks(np.arange(0, 17.5, step=1.0))

#y_ticks=['y tick 1','y tick 2','y tick 3']
#ax.set_yticklabels(y_ticks, rotation=0, fontsize=8)
#plt.yticks(np.arange(0, 120, step=25))
plt.yticks(range(0,101,20))

#plt.tight_layout(margins=5)
plt.margins(0.13)

program_names = ["TC", "Priority", "MOVTC", "Payload"]

A = np.array([83, 87, 84, 87])
B = np.array([17, 13, 16, 13])
X = np.arange(len(A))

#N = 8
#A = np.random.random(N)
#B = np.random.random(N)
#C = np.random.random(N)
#X = np.arange(N)
plt.bar(X, A, width=0.20, color = 'w', hatch = ' ', label='Analysis', align='center',)
plt.bar(X, B, width=0.20, bottom = A, color = 'w', hatch = 'x', label='Leak', align='center',)


plt.xticks(X, program_names, rotation=0)

#ax.legend(loc="upper left", bbox_to_anchor=(1,1), ncol=2, fontsize='x-small')
#plt.subplots_adjust(right=0.75, bottom=0.4)
#plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

#plt.legend()

#ax.legend()

plt.legend(frameon=False, prop={'size': 20}, ncol=2, columnspacing=0.5, handletextpad=0.5, bbox_to_anchor=(1.0,1.03))

#plt.xlabel('time (second)', fontsize=24)
plt.ylabel('Percentage (%)', fontsize=20)
#ax.yaxis.set_label_coords(0, 0) 

#plt.show()
#fig.tight_layout()
fig.savefig('leak_vs_analysis.png', dpi=300)
