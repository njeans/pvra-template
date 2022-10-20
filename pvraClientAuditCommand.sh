#!/bin/bash

if [ "$1" == "data" ]; then
  echo -n "[client] Posting proof of omission with data to billboard for audit_num $3 omission_detected: "
  python3 $PROJECT_ROOT/billboard/billboard.py user_prove_omission_data $2 $3
else
  echo -n "[client] Posting proof of omission with sig to billboard omission_detected: "
  python3 $PROJECT_ROOT/billboard/billboard.py user_prove_omission_sig $2 cResponse.json
fi
