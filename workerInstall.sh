#!/bin/sh

echo 'CVMFS_HTTP_PROXY="http://10.0.0.162:3128"' > /etc/cvmfs/default.local
cvmfs_config reload

if [ ! -f /tmp/install_done ]; then

touch /tmp/install_done

# Ensures that hostname is set before HTCondor is started.
# This ensures that Senlin and HTCondor has the same node name.
# The solution works more efficiently when this is the case.
hostname $(curl http://169.254.169.254/latest/meta-data/hostname | sed "s/.novalocal//g")

cat > /etc/condor/drain_time_limit_check.sh <<-'EOF'
DRAIN_TIME_LIMIT_CHECK_SH_FILE
EOF
chmod +x /etc/condor/drain_time_limit_check.sh
/etc/condor/drain_time_limit_check.sh &>/dev/null &

echo -n STATIC_IP >> /etc/hosts
echo "  sveinung.hib.no      sveinung" >> /etc/hosts
echo "10.0.0.210  cs1.hib.no      cs1" >> /etc/hosts

echo "123" > /tmp/pool_password
echo "ALLOW_WRITE = *" > /etc/condor/condor_config.local
echo "ALLOW_READ = *" >> /etc/condor/condor_config.local
echo "CONDOR_HOST = STATIC_IP" >> /etc/condor/condor_config.local
echo "TRUST_UID_DOMAIN = True" >> /etc/condor/condor_config.local
echo "ALLOW_NEGOTIATOR = *" >> /etc/condor/condor_config.local
echo "ALLOW_NEGOTIATOR_SCHEDD = *" >> /etc/condor/condor_config.local
echo "UPDATE_COLLECTOR_WITH_TCP = TRUE" >> /etc/condor/condor_config.local
echo "START = TRUE" >> /etc/condor/condor_config.local
echo "HOSTALLOW_WRITE = *" >> /etc/condor/condor_config.local
echo "DAEMON_LIST = MASTER, STARTD" >> /etc/condor/condor_config.local

echo "DRAIN_TIME_LIMIT = 1200" >> /etc/condor/condor_config.local
echo "ALLOW_CONFIG = \$(CONDOR_HOST),\$(IP_ADDRESS)" >> /etc/condor/condor_config.local
echo "ENABLE_RUNTIME_CONFIG = True" >> /etc/condor/condor_config.local
echo "SETTABLE_ATTRS_CONFIG = START,DRAIN_TIMESTAMP" >> /etc/condor/condor_config.local

echo "STARTD_CRON_JOBLIST = $(STARTD_CRON_JOBLIST) test" >> /etc/condor/condor_config.local
echo "STARTD_CRON_TEST_EXECUTABLE = /etc/condor/drain_time_limit_check.sh" >> /etc/condor/condor_config.local
echo "STARTD_CRON_TEST_PERIOD = 60s" >> /etc/condor/condor_config.local

echo "UPDATE_INTERVAL = 20" >> /etc/condor/condor_config.local

systemctl enable condor
systemctl start condor

fi
