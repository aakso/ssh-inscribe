#!/bin/sh
MAIN=$1
if [ "$1" = "" ]
then
	echo "Please specify a version name. Ex ./perf main1"
	exit 1
fi

echo "Compiling..."
go build main.go
mv main $MAIN
echo "Perf..."
./xtime.sh ./$MAIN
echo "Profiling..."
./$MAIN -cpuprofile=${MAIN}.prof
echo "OK now launch: go tool pprof $MAIN ${MAIN}.prof"
# go tool pprof ./$MAIN ${MAIN}.prof
