"""
    This python script is responsible for testing all the test cases in 
    this directory.

    each test*.c file has a real output and an expected output.

    This python script compare real and expected output together.
"""

import sys
import os
import json
import re
import traceback
import py_test_list

if __name__ == "__main__":
    current_dir = os.path.abspath(os.path.dirname(__file__))
    tmp_file = "{}/tmp_result".format(current_dir)
    data = None
    try:
        with open(tmp_file) as f:
            data = f.read()
        # end with
    except Exception as e:
        print(traceback.format_exc())
        exit(1)
    # end except
    test_file_name = sys.argv[1]
    test_file_name = "func_{}".format(test_file_name[:test_file_name.rfind(".c")])
    if not data:
        print("ERROR: Can not find the output of the test file")
        exit(1)
    # end if
    func_list = [x for x in dir(py_test_list) if x.startswith("func_")]
    if test_file_name not in func_list:
        print("ERROR: test function not found in py_test_list.py....")
        exit(1)
    # end if
    executable = getattr(py_test_list, test_file_name)
    exit(executable(data))
# end main
