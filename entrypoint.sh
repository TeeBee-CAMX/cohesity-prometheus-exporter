#!/bin/sh
 
# Fail if required args are missing
if [ -z "$COHESITY_VIP" ]; then
  echo "ERROR: COHESITY_VIP (-v) is required"
  exit 1
fi
 
if [ -z "$COHESITY_USER" ]; then
  echo "ERROR: COHESITY_USER (-u) is required"
  exit 1
fi
 
# Execute exporter with required args + anything else passed
exec python /app/cpe.py \
  -v "$COHESITY_VIP" \
  -u "$COHESITY_USER" \
  "$@"
