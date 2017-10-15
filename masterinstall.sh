#!/bin/sh

sed -i s/'PasswordAuthentication yes'/'PasswordAuthentication no'/g /etc/ssh/sshd_config
systemctl restart sshd

echo 'CVMFS_HTTP_PROXY="http://10.0.0.162:3128"' > /etc/cvmfs/default.local
cvmfs_config reload

# Change hostname to match AliEn certificate
MASKIN=sveinung.hib.no
hostname $MASKIN
echo "HOSTNAME=\"$MASKIN\"" >> /etc/sysconfig/network # Make it persistant through reboot

if [ ! -f /tmp/install_done ]; then

#Disable selinux as condor won't run with it enabled
setenforce 0

echo -n "STATIC_IP " >> /etc/hosts
hostname >> /etc/hosts
echo "10.0.0.210  cs1.hib.no      cs1" >> /etc/hosts

echo "ALLOW_WRITE = *" > /etc/condor/condor_config.local
echo "ALLOW_READ = *" >> /etc/condor/condor_config.local
echo "TRUST_UID_DOMAIN = True" >> /etc/condor/condor_config.local
echo "ALLOW_NEGOTIATOR = *" >> /etc/condor/condor_config.local
echo "ALLOW_NEGOTIATOR_SCHEDD = *" >> /etc/condor/condor_config.local
echo "UPDATE_COLLECTOR_WITH_TCP = TRUE" >> /etc/condor/condor_config.local
echo "ALLOW_DAEMON = *" >> /etc/condor/condor_config.local
echo "SEC_DAEMON_AUTHENTICATION = OPTIONAL" >> /etc/condor/condor_config.local
echo "SEC_DAEMON_INTEGRITY = OPTIONAL" >> /etc/condor/condor_config.local

echo "HOSTALLOW_WRITE = *" >> /etc/condor/condor_config.local
echo "DAEMON_LIST = COLLECTOR, MASTER, NEGOTIATOR, SCHEDD" >> /etc/condor/condor_config.local

echo "CLASSAD_LIFETIME = 30" >> /etc/condor/condor_config.local
echo "NEGOTIATOR_UPDATE_INTERVAL = 20" >> /etc/condor/condor_config.local
echo "COLLECTOR_UPDATE_INTERVAL = 20" >> /etc/condor/condor_config.local
echo "SCHEDD_INTERVAL = 20" >> /etc/condor/condor_config.local
echo "MASTER_UPDATE_INTERVAL = 20" >> /etc/condor/condor_config.local

systemctl enable condor
systemctl start condor

wc_notify --data-binary '{"status": "SUCCESS"}'

adduser -u 41743 alienvo
groupmod -g 41743 alienvo

#Install CA
export hash=97c37926
wget -P /tmp http://eple.hib.no/grid/globus-simple-ca-$hash-1.0-1.el6.noarch.rpm
pushd /tmp
rm -R /etc/grid-security/certificates
rpm2cpio globus-simple-ca-$hash-1.0-1.el6.noarch.rpm | cpio -idmv
cp -Rp etc/grid-security/certificates /etc/grid-security/
export oldhash=$(openssl x509 -noout -subject_hash_old -in /etc/grid-security/certificates/$hash.0)
/cvmfs/grid.cern.ch/emi-ui-3.17.1-1.sl6umd4v2/usr/sbin/grid-default-ca -ca $hash

for f in /etc/grid-security/certificates/*$hash*; do
  newf=${f##*/}
  oldf=$(echo $newf | sed -e "s|$hash|$oldhash|")
  ln -s $newf /etc/grid-security/certificates/$oldf
done

ln -s /etc/grid-security/certificates/$hash.0 /etc/pki/tls/certs/$hash.0
ln -s $hash.0 /etc/pki/tls/certs/$oldhash.0

mkdir -p /share/home
chmod 777 /share
chmod 777 /share/home

mkdir -p /share/vo/packman
chown -R alienvo.alienvo /share/vo

cat >> /home/alienvo/.bash_profile <<-EOF
export HTCONDOR_LOG_PATH="/home/alienvo"

export ALIEN_USER=aliprod
export ALIEN_CM_AS_LDAP_PROXY=10.0.0.210:8084
export ALIEN_LDAP_DN="10.0.0.210:8389/o=ALIENBERGEN,dc=hib,dc=no"
export VO_ALICE_SW_DIR=/cvmfs/alice.cern.ch
export ALIEN_INS=\$VO_ALICE_SW_DIR
export ALIEN_ROOT=\$VO_ALICE_SW_DIR
export GLOBUS_LOCATION=/cvmfs/grid.cern.ch/Grid/globus
export PATH=\$ALIEN_ROOT/bin:\$ALIEN_ROOT/api/bin:\$GLOBUS_LOCATION/bin:\$HOME/bin:\$PATH:\$VO_ALICE_SW_DIR/bin
export ALIEN=\$ALIEN_ROOT
export ALIEN_NTP_HOST=10.0.0.15
export ALIEN_HOME=\$HOME/.alien
export GSHELL_ROOT=\$ALIEN_ROOT/api
export ALIEN_DOMAIN=sveinung.hib.no
export ALIEN_ORGANISATION=ALIENBERGEN
EOF

mkdir -p /home/alienvo/.alien
cat > /home/alienvo/.alien/Environment <<-EOF
export ALIEN_WORKDIR=/home/alienvo/alien/work #Må stemme med verdi i alienbergen.conf for WORK_DIR
export ALIEN_CACHE=/home/alienvo/alien/cache  #Må stemme med verdi i alienbergen.conf for CACHE_DIR
EOF
cat > /home/alienvo/.alien/alienbergen.conf <<-EOF
TMP_DIR   /home/alienvo/alien/tmp
LOG_DIR   /home/alienvo/alien/log
WORK_DIR  /home/alienvo/alien/work
CACHE_DIR /home/alienvo/alien/cache

# I LOG_DIR legges bla. STDOUT og STDERR fra Torque. Filer flyttes fra /var/lib/torque/spool/
# på workernode til LOG_DIR på Torque-server. Dersom ikke LOG_DIR er på delt
# filsystem benyttes rcp, evt. scp. Mappe TMP_DIR inneholder på workernode info om kjøring.
# Også dette er nyttig å ha på server. Har derfor lagt alle mappene over på delt filsystem.

#CLUSTERMONITOR_ADDRESS cs1.hib.no
EOF

mkdir -p /home/alienvo/.alien/etc/aliend/ALIENBERGEN
cat > /home/alienvo/.alien/etc/aliend/startup.conf <<-EOF
#Startup configuration for alien
ALIEN_ORGANISATIONS="ALIENBERGEN"
EOF

cat > /home/alienvo/.alien/etc/aliend/ALIENBERGEN/startup.conf <<-EOF
#Startup configuration for alien
#User under which services will run locally. The local linux-user, not the alien user!
#Used if root is starting the services
AliEnUser=alienvo

AliEnCommand="/cvmfs/alice.cern.ch/bin/alien"
#Services to start (no need for explicit FTD after version 2.17)
#AliEnServices="MonaLisa Monitor PackMan CE CMreport"
AliEnServices="Monitor CE CMreport"
EOF

mkdir /home/alienvo/.alien/globus

ln -s /home/alienvo /share/home/alienvo

# Adding certificate

cat > /home/alienvo/.alien/globus/usercert.pem <<'EOF'
############ Insert Grid certificate here ############
EOF

cat > /home/alienvo/.alien/globus/userkey.pem <<'EOF'
############ Insert private key here ############
EOF

chmod 400 /home/alienvo/.alien/globus/userkey.pem

mkdir /home/alienvo/.globus
cp /home/alienvo/.alien/globus/usercert.pem /home/alienvo/.globus/
cp /home/alienvo/.alien/globus/userkey.pem /home/alienvo/.globus/

chown -R alienvo:alienvo /home/alienvo/

mkdir /home/alienvo/.ssh
cat > /home/alienvo/.ssh/authorized_keys <<EOF
############ Insert Senlin policy SSH puplic key here ############
EOF

su - -c "/cvmfs/alice.cern.ch/bin/aliend start" alienvo


wc_notify --data-binary '{"status": "SUCCESS"}'
sleep 60
wc_notify --data-binary '{"status": "SUCCESS"}'

touch /tmp/install_done

fi
