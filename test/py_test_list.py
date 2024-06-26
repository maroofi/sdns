"""
    Add your test functions checkers here:
    Rules:
        1. All the functions must be like "func_<name of the c file without extension>"
            for example: there is a .c file in this directory named "test1.c".
            the output of "test1.c" will be evaluated by the function "func_test1".
            the data parameter of the func_test1 is the output of the test1.c file.
        2. All functions must return 0 on success or any other value greater than zero on fail
"""

import os
import sys
import json
import re
try:
    from jsoncomparison import Compare, NO_DIFF
except:
    print("ERROR: you must install jsoncomparison package (pip install jsoncomparison)")
    sys.exit(2)
# end try


def func_test1(data):
    data = json.loads(data)
    real_answer = json.loads(open("json_real_for_test1.json").read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test2(data):
    data = json.loads(data)
    real_answer = json.loads(open("json_real_for_test2.json").read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test3(data):
    data = json.loads(data)
    real_answer = json.loads(open("json_real_for_test3.json").read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test4(data):
    data = json.loads(data)
    real_answer = json.loads(open("json_real_for_test4.json").read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def




