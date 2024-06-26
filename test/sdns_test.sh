#!/bin/bash

script_dir=$(dirname "$(realpath $0)")
echo "Current directory is: $script_dir"

cd $script_dir

sdns_lib_dir=$(realpath $script_dir/../bin)
echo "Library path: $sdns_lib_dir"

echo "Adding library path to LD_LIBRARY_PATH..."
export LD_LIBRARY_PATH=$sdns_lib_dir:$LD_LIBRARY_PATH

# get the list of the test C codes
test_files=$(ls -1 test*.c)

for c_file in $test_files
do
    echo -n "Compiling.....$c_file..."
    gcc -g -o test $c_file -I../include  -L$sdns_lib_dir -lsdns -ljansson
    if [ $? -ne 0 ]
    then
        echo ""
        echo "Error in compiling $c_file..."
        echo "Tests failed......exit"
        exit 1
    fi
    echo -n "Executing ./test ($c_file)....."
    ./test 2>&1 > tmp_result
    if [ $? -ne 0 ]
    then
        echo ""
        echo "Error in executing $c_file"
        echo "Tests failed......exit"
        rm -f tmp_result
        exit 1
    fi
    python3 py_test_sdns.py $c_file
    if [ $? -ne 0 ]
    then
        echo ""
        echo "Error in the output of $c_file"
        echo "Tests failed......exit"
        rm -f tmp_result
        exit 1
    fi
    echo "Success"
    # remove the result temporary file
    rm -f tmp_result
    rm -f test
done
