#!/bin/sh

ps auxww | awk '/[f]ind_new_domains.py/ {print "kill -TERM " $2}' | sh

./download_malware_domains.sh

nohup python find_new_domains.py -c example_config.yml -i enp4s0 &
