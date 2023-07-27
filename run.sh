#! /bin/bash
echo "refclock PHC /dev/ptp0 poll 2" >> /etc/chrony/chrony.conf
chronyd -d -d &
sleep 10
chronyc sources

enclave-issue
