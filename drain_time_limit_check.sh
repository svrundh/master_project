#!/bin/sh

DRAIN_TIMESTAMP=$(condor_config_val -startd DRAIN_TIMESTAMP)

if [  "$DRAIN_TIMESTAMP" == "Not defined" ]; then
  exit
else
DRAIN_TIME_LIMIT=$(condor_config_val DRAIN_TIME_LIMIT)
TIME=$(date +%s)

if [ $(( $TIME - $DRAIN_TIMESTAMP )) -gt  $DRAIN_TIME_LIMIT ]; then
  condor_config_val -startd -rset "START = True" &>/dev/null
  condor_reconfig &>/dev/null
fi

fi
