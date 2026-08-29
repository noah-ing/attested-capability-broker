#!/bin/sh
set -eu

exec swtpm socket \
  --tpm2 \
  --tpmstate dir=/var/lib/atcap-swtpm \
  --server type=tcp,port=2321,bindaddr=0.0.0.0 \
  --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
  --flags not-need-init,startup-clear

