#! /bin/bash
if [[ -z $1 ]]; then
	echo "entrypoint not found."
	exit 1
fi
echo "refclock PHC /dev/ptp0 poll 2" >> /etc/chrony/chrony.conf
chronyd -d -d &
sleep 10
chronyc sources

$1
