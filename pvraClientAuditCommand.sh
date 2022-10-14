#!/bin/bash

if [ "$3" == "data" ]; then
  echo -n "[client] Posting proof of omission with data to billboard for audit_num $2 omission_detected: "
  python3 $PROJECT_ROOT/billboard/billboard.py user_prove_omission_data $1 $2
else
  echo -n "[client] Posting proof of omission with sig to billboard omission_detected: "
  python3 $PROJECT_ROOT/billboard/billboard.py user_prove_omission_sig $1 cResponse.json
fi
