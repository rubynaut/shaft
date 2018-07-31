#!/bin/bash

echo $1 `wc -c ${1}.bin` $FLAGS
# $1 common prefix of samples
for sample in ${1}-*.bin; do
    shaft $FLAGSt -t ${T:-1} -f $sample -s `cat $1.sha`
done
