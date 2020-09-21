import os
import sys
import math
import random
import numpy as np
import statistics as stat
from scipy.stats import sem

from os import listdir
from os.path import isfile, join

import pandas as pd
import altair as alt
from altair import datum
from altair_saver import save

def get_movtc_count(filename, req_gadgets):
	MR = MRCONST = ST = STCONSTEX = STCONST = LM = LMEX = SYS = 0
	count = 0
	complete = False
	with open(filename) as f:
		for line in f.readlines():
			#print(line.strip())
			tokens = line.strip().split()
			#print(len(tokens))
			if (len(tokens) == 2 and tokens[1] == req_gadgets):
				#data.append(int(tokens[0]))
				complete = True
				#print(line.strip())
			if (len(tokens) == 8 and complete == True):
				tokens = line.strip().split()
				MR += int(tokens[0])
				MRCONST += int(tokens[1])
				ST += int(tokens[2])
				STCONSTEX += int(tokens[3])
				STCONST += int(tokens[4])
				LM += int(tokens[5])
				LMEX += int(tokens[6])
				SYS += int(tokens[7])

				count += 1
				complete = False
	if count < 1:
		print(filename, 'All zero MOVTC COUNT detected!')
		return 0, 0, 0, 0, 0, 0, 0, 0

	return MR/count, MRCONST/count, ST/count, STCONSTEX/count, STCONST/count, LM/count, LMEX/count, SYS/count

def get_avg_movtc_count(datadir, req_gadgets):
	onlyfiles = [f for f in listdir(datadir) if isfile(join(datadir, f))]
	count = 0
	MR = MRCONST = ST = STCONSTEX = STCONST = LM = LMEX = SYS = 0
	for file in onlyfiles:
		if file.lower().endswith(('.txt')) == False:
			continue

		mMR, mMRCONST, mST, mSTCONSTEX, mSTCONST, mLM, mLMEX, mSYS = get_movtc_count(join(datadir, file), req_gadgets)
		MR += mMR
		MRCONST += mMRCONST 
		ST += mST 
		STCONSTEX += mSTCONSTEX 
		STCONST += mSTCONST 
		LM += mLM 
		LMEX += mLMEX 
		SYS += mSYS
		count += 1

	return round(MR/count), round(MRCONST/count), round(ST/count), \
		round(STCONSTEX/count), round(STCONST/count), round(LM/count), \
		round(LMEX/count), round(SYS/count)



def get_min_max_avg(data):
	return min(data), max(data), float("{:.2f}".format(stat.mean(data)))

def calculate_leak_vs_gadget_analysis_time(data):
	lines = data.split('\n')
	gcreate_time = 0
	glookup_time = 0
	total_time = 0
	for line in lines:
		#print(line)
		if not line:
			continue
		tokens = line.split()
		#print(tokens)
		#print(tokens[1], tokens[2], tokens[3])
		gcreate_time += int(tokens[1])
		glookup_time += int(tokens[2])
		total_time = int(tokens[3])

	#print(glookup_time, gcreate_time, total_time)

	return glookup_time, gcreate_time, total_time

def get_leak_vs_gadget_analysis_time(filename, req_gadgets):
	lookup_time = 0
	analysis_time = 0
	total_time = 0
	total_count = 0
	with open(filename) as f:
		everything_before_pageno = ""
		for line in f.readlines():
			tokens = line.strip().split()

			if (line.startswith('0x', 0, len('0x'))):
				continue

			if len(tokens) == 2 and int(tokens[1]) != int(req_gadgets):
				everything_before_pageno = ""
				continue

			if len(tokens) == 2 and int(tokens[1]) == int(req_gadgets):
				#print(everything_before_pageno)
				ltime, atime, ttime = calculate_leak_vs_gadget_analysis_time(everything_before_pageno)
				lookup_time += ltime
				analysis_time += atime
				total_time += ttime
				total_count += 1
				#print(ltime, atime )
				#print('===========================')
				everything_before_pageno = ""
				continue

			everything_before_pageno += line

	return lookup_time/total_count, analysis_time/total_count, total_time/total_count

def get_average_leak_vs_analysis(datadir, req_gadgets):
	onlyfiles = [f for f in listdir(datadir) if isfile(join(datadir, f))]
	lookup_time = 0
	analysis_time = 0
	total_time = 0
	total_count = 0
	for file in onlyfiles:
		if file.lower().endswith(('.txt')) == False:
			continue

		ltime, atime, ttime = get_leak_vs_gadget_analysis_time(join(datadir, file), req_gadgets)
		lookup_time += ltime
		analysis_time += atime
		total_time += ttime
		total_count += 1

	avg_leak_time = lookup_time/total_count
	avg_analysis_time = analysis_time/total_count
	avg_total_time = total_time/total_count

	print("{:.2f}".format((avg_total_time-avg_analysis_time)/avg_total_time), "{:.2f}".format(avg_analysis_time/avg_total_time))

def get_rerand_intervals(filename, req_gadgets):
	data = []
	with open(filename) as f:
		for line in f.readlines():
			if not line:
				continue
			#print(line.strip())
			tokens = line.strip().split()
			if (len(tokens) == 2 and tokens[1] == req_gadgets):
				data.append(int(tokens[0]))
	return data

def get_average_range(datadir, req_gadgets):
	onlyfiles = [f for f in listdir(datadir) if isfile(join(datadir, f))]
	min_times = []
	max_times = []
	avg_times = []
	for file in onlyfiles:
		if file.lower().endswith(('.txt')) == False:
			continue
		
		#print(join(datadir, file))
		data = get_rerand_intervals(join(datadir, file), req_gadgets)
		min_t, max_t, avg_t = get_min_max_avg(data)
		min_times.append(min_t)
		max_times.append(max_t)
		avg_times.append(avg_t)
		#print(file, min_t, max_t, avg_t)
	print('Min time range: ', min(min_times), max(min_times), "{:.2f}".format(stat.mean(min_times)), "{:.2f}".format(stat.stdev(min_times)))
	print('Max time range: ', min(max_times), max(max_times), "{:.2f}".format(stat.mean(max_times)), "{:.2f}".format(stat.stdev(max_times)))
	print('Avg time range: ', min(avg_times), max(avg_times), "{:.2f}".format(stat.mean(avg_times)), "{:.2f}".format(stat.stdev(avg_times)))

def print_trajectory(filename, req_gadgets):
	data = get_rerand_intervals(filename, req_gadgets)
	min_time, _, avg_time = get_min_max_avg(data)
	closest = min(data, key=lambda x:abs(x-min_time))
	#print(min_time)

	found = False
	with open(filename) as f:
		everything_before_pageno = ""
		for line in f.readlines():
			if not line:
				continue

			tokens = line.strip().split()

			if (line.startswith('0x', 0, len('0x'))):
				continue

			if len(tokens) == 2 and int(tokens[1]) != int(req_gadgets):
				everything_before_pageno = ""
				continue

			if len(tokens) == 2 and int(tokens[1]) == int(req_gadgets):
				if float(tokens[0]) == closest:
					found = True
					return everything_before_pageno
				else:
					everything_before_pageno = ""
					continue

			everything_before_pageno += line

	return None

def new_leaks_on_trajectory(filename, req_gadgets):
	app = os.path.basename(filename).split(".")[0].strip()
	raw_lines = print_trajectory(filename, req_gadgets)
	data = []
	lines = raw_lines.split('\n')
	first = True
	for line in lines:
		#print(line)
		tokens = line.strip().split()
		if len(tokens) < 2:
			continue

		if first == True:
			#print(app, tokens[3], tokens[4])
			tmp = [app, int(tokens[3])/1000.0, tokens[4], 0]
			data.append(tmp)
			previous = tokens[4]
			first = False
			continue
		if previous == tokens[4]:
			continue

		#print(app, tokens[3], tokens[4])
		if tokens[4] == req_gadgets:
			tmp = [app, int(tokens[3])/1000, tokens[4], 1]
		else:
			tmp = [app, int(tokens[3])/1000, tokens[4], 0]
		data.append(tmp)

		previous = tokens[4]
	
	return data

def generate_trajectory_data(datadir, req_gadgets):
	onlyfiles = [f for f in listdir(datadir) if isfile(join(datadir, f))]
	data = []
	for file in onlyfiles:
		if file.lower().endswith(('.txt')) == False:
			continue
		
		#print(join(datadir, file))
		#print(new_leaks_on_trajectory(join(datadir, file), req_gadgets))
		data.extend(new_leaks_on_trajectory(join(datadir, file), req_gadgets))

	return pd.DataFrame(data, columns=['name', 'time', 'leaks', 'ub'])

def draw_rerand_trajectory(source):
	upperbounds = source[source['ub'] == 1][['name', 'time', 'leaks']]
	#print(upperbounds)
	lines = alt.Chart(source, height=600, width=900,).mark_line(strokeDash=[5,4]).encode(
	    	#x='time',
	    	y='name',
	    	x=alt.Y('time', title='time (second)', axis=alt.Axis(tickMinStep = 0.5)),
	    	#color='name',
	    	#strokeDash='name:0',
	    	#color='color',
	    	#stroke='color'
	    	color=alt.Color('name', legend=None)
	)

	circles = alt.Chart(source).mark_circle(
	    	color='lightslategray',
	    	#color=alt.value("#5B5B61"),
	    	opacity=1.0,
	    	size=80.0
	).encode(
	   	y='name',
	    	x='time'
	)

	circles2 = alt.Chart(upperbounds).mark_circle(
	    	color='black',
	    	opacity=1.0,
	    	size=100.0,
	    	#dx = -4.0
	).encode(
	    	y='name',
	    	x='time'
	    	#facet='name'
	)

	border = alt.Chart(source).mark_image(
	      	width=20,
	      	height=20
	   ).encode(
	    	y='name',
	    	x='time',
	    	url='img'
	)

	annotation = alt.Chart(source).mark_text(
	    	align='left',
	    	baseline='middle',
	    	opacity=1.0,
	    	fontSize = 18,
	    	dx = -3.5,
	    	dy = -13.0
	).encode(
	    	x='time',
	    	y='name',
	    	text='leaks'
	)

	#(lines + circles + annotation + border).save('mychart2.html', scale_factor=10.0)

	chart = alt.layer(lines, circles, circles2, annotation).configure_view(
	    	stroke='transparent'
	).configure_axis(
	    	labelFontSize=22,
	   	titleFontSize=22,
	   	#grid=False
	   	#tickOffset = 10
	   	tickCount = 20
	)
	#chart
	save(chart, "chart.html", scale_factor=2.0) 

def get_data_for_errorbar(datadir, req_gadgets):
	onlyfiles = [f for f in listdir(datadir) if isfile(join(datadir, f))]
	min_times = []
	max_times = []
	avg_times = []
	data = []
	for file in onlyfiles:
		if file.lower().endswith(('.txt')) == False:
			continue
		
		app = os.path.basename(file).split(".")[0].strip()
		#print(join(datadir, file))
		
		tmp = get_rerand_intervals(join(datadir, file), req_gadgets)
		for item in tmp:
			jitter=math.sqrt(-2*math.log(random.random()))*math.cos(2*math.pi*random.random())
			data.append([app, jitter, item/1000.0, 0])
		data.append([app, 0, min(tmp)/1000.0, 1])
		data.append([app, 0, max(tmp)/1000.0, 2])
		data.append([app, 0, stat.mean(tmp)/1000.0, 3])
		data.append([app, 0, (stat.mean(tmp)+sem(tmp))/1000.0, 4])
		data.append([app, 0, (stat.mean(tmp)-sem(tmp))/1000.0, 4])

	return pd.DataFrame(data, columns=['name', 'jitter', 'time', 'which'])

def draw_location_impact(source):
	stripplot =  alt.Chart(source, width=40).mark_circle(
		size=18,
	    	color='lightgray',
	).transform_filter(
	     	datum.which == 0
	).encode(
	    	x=alt.X(
	        	'jitter:Q',
	        	title=None,
	        	axis=alt.Axis(values=[0], ticks=True, grid=False, labels=False),
	        	#scale=alt.Scale(),
	    	),
	    	y=alt.Y('time:Q', title="time (second)"),
	    	color=alt.Color('which:N', legend=None),
	    	shape=alt.Shape('name', scale=alt.Scale(range=['cross', 'circle', 'square', 'triangle-right', 'diamond']))
	)
	
	error_bars = alt.Chart(source).mark_line(
	    color='black',
	).transform_filter(
		datum.which == 4
	).encode(
	  	x=alt.X('jitter:Q', title=None, scale=alt.Scale(zero=False)),
	  	y=alt.Y('time:Q', title="time (second)")
	)

	mins = alt.Chart(source).transform_filter(
	     	datum.which == 1
	).mark_point(
	    	color='black',
	    	#color=alt.value("#5B5B61"),
	    	opacity=1.0,
	    	size=80.0
	).encode(
	  	x=alt.X('jitter:Q', title=None, scale=alt.Scale(zero=False)),
	  	y=alt.Y('time:Q', title="time (second)"),
	     	shape = alt.Shape("which:N", scale = alt.Scale(range=["triangle-down", "triangle-up"],zero=False)),
	)

	maxs = alt.Chart(source).transform_filter(
	     	datum.which == 2
	).mark_point(
	    	color='black',
	    	#color=alt.value("#5B5B61"),
	    	opacity=1.0,
	    	size=80.0
	).encode(
	  	x=alt.X('jitter:Q', title=None, scale=alt.Scale(zero=False)),
	  	y=alt.Y('time:Q', title="time (second)"),
	    	shape = alt.Shape("which:N", scale = alt.Scale(range=["triangle-down", "triangle-up"],zero=False)),
	)

	avgs = alt.Chart(source).transform_filter(
	    	 datum.which == 3
	).mark_circle(
	    	color='black',
	    	#color=alt.value("#5B5B61"),
	    	opacity=1.0,
	    	size=80.0
	).encode(
	  	x=alt.X('jitter:Q', title=None, scale=alt.Scale(zero=False)),
	  	y=alt.Y('time:Q', title="time (second)"),
	    	#shape = alt.Shape("which:N", scale = alt.Scale(range=["cross"],zero=True)),
	)

	#lay the two and facet 
	chart = alt.layer(stripplot, mins, maxs, avgs, error_bars, data=source).facet(
	    	column=alt.Column(
	        	'name:N',
	        	header=alt.Header(
	            		labelAngle=-30,
	            		titleOrient='top',
	            		labelOrient='bottom',
	            		labelAlign='center',
	            		labelPadding=35,
	            		labelFontSize=22,
	        	)
	    	)
	).configure_view(
	    	stroke='transparent',
	    	height = 350,
	    	width = 500,
	).configure_facet(
	    	spacing=10
	).configure_axis(
	    	labelFontSize=22,
	    	titleFontSize=22,
	    	grid=False,
	    	tickOffset = 10,
	    	tickCount = 15
	)
	#chart
	save(chart, "locations.html", scale_factor=6.0) 

#print(get_avg_movtc_count(sys.argv[1], sys.argv[2]))
#get_average_leak_vs_analysis(sys.argv[1], sys.argv[2])
#leak_time, analysis_time, total_time = get_leak_vs_gadget_analysis_time(sys.argv[1], sys.argv[2])
#print(leak_time, analysis_time, total_time)
#result = print_trajectory(sys.argv[1], sys.argv[2])
#print(result)
#data = new_leaks_on_min_trajectory(sys.argv[1], sys.argv[2])
#print(data)
#result = generate_trajectory_data(sys.argv[1], sys.argv[2])
#print(result)
#for item in result:
#	print(item)
#draw_rerand_trajectory(result)
#data = get_data_for_errorbar(sys.argv[1], sys.argv[2])
#print(data)
#data.to_csv('errorbar.csv', index=False) 
#draw_location_impact(data)

def main():
	if (len(sys.argv) < 4):
		print("Usage: python3 analyze_data.py <operation> <directory [tc, priority, movtc, payload1]> <# of required gadgets>")
		sys.exit(0)
	
	datadir = sys.argv[2]
	req_gadgets = sys.argv[3]
	if (sys.argv[1] == 'range'):
		get_average_range(datadir, req_gadgets)
	elif (sys.argv[1] == 'time'):
		get_average_leak_vs_analysis(datadir, req_gadgets)
	else:
		print('pass')
	
if __name__ == "__main__":
	main()
