#!/bin/bash

pid=$1
address=$2
rerand=$3
limit=$4
filename=$5


sudo ./jitrop $pid $address $rerand 1 $limit > dataccs/$filename'_tc.txt'
sleep 2
sudo ./jitrop $pid $address $rerand 2 $limit > dataccs/$filename'_prio.txt'
sleep 2
sudo ./jitrop $pid $address $rerand 3 $limit > dataccs/$filename'_mv.txt'
sleep 2
sudo ./jitrop $pid $address $rerand 4 5 > dataccs/$filename'_mvc.txt'
sleep 2
#sudo ./jitrop $pid $address $rerand 5 10 > dataccs/$filename'_p1.txt'
#sleep 2

