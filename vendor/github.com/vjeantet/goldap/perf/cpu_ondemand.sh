#!/bin/bash
for i in /sys/devices/system/cpu/cpu[0-7]
do
	echo ondemand > $i/cpufreq/scaling_governor
done
