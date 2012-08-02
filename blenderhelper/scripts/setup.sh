modprobe nbd
nvidia-settings&
/etc/init.d/dns.tap100 start
/etc/init.d/postgresql-9.1 start
/etc/init.d/snort start
kvmmanager.sh start /home/jab/vms/ksploit/xpprosp2 
kvmmanager.sh start /home/jab/vms/ksploit/gentoosqli
/opt/metasploit3/msf3/msfconsole -r kinectasploit.rc
