#!/bin/bash

for i in {1..7}; do
    if [[ "$1" == "enable" ]]; then
        echo 1 > /sys/devices/system/cpu/cpu$i/online
    elif [[ "$1" == "disable" ]]; then
        echo 0 > /sys/devices/system/cpu/cpu$i/online
    else
        echo 'illegal parameter'
    fi
done
grep "processor" /proc/cpuinfo

#sudo ./onoffcpu.sh enable
#sudo ./onoffcpu.sh disable
