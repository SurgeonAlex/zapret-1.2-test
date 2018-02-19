#!/bin/bash

data=$(/bin/date +%d.%m.%Y_%H:%M)

for dir in $(/usr/bin/find /usr/local/etc/zapret/old_dump_archive -type f -mtime +7);
do
/bin/rm -rf $dir
echo "Old Dump Arch dir ${dir} is Clean at ${data}" >> /var/log/old_dump_date_clean.log
done
