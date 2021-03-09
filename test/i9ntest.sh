#!/bin/bash

# run some integration tests

for path in ../../iam-messaging/i9n ../i9n
do
  cat $path/TESTS | while read fname
  do
     [[ -z $fname ]] && continue
     [[ $fname == *\#* ]] && continue
     txt="${path}/${fname}.txt"
     enc="${path}/${fname}.enc"
     echo "$txt"
     ./i9ntest -v -s $txt -e $enc
  done
done
