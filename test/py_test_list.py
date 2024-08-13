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

DATA_DIR = "{}/data".format(os.path.abspath(os.path.dirname(__file__)))



def func_test1(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_for_test1.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test2(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_for_test2.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test3(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_for_test3.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test4(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_for_test4.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_testapi1(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_cookie1(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_cookie2(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_cookie3(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid1(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid2(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid3(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid4(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid5(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid6(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_testapi_nsid7(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_soa_1(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_txt_1(data):
    assert(data.strip() == "success")
    return 0
# end def


def func_test_apiget_answer_a(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_apiget_answer_hinfo(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_apiget_answer_ns(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_apiget_answer_srv(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_apiget_answer_mx(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_apiget_answer_cname(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_apiget_answer_soa(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_apiget_answer_txt(data):
    assert(data.strip() == "success")
    return 0
# end def

def func_test_api_getquestion(data):
    assert(data.strip() == "success");
    return 0;
# end def

def func_test_create_response_from_query(data):
    assert(data.strip() == "success");
    return 0;
# end def

def func_test_caa(data):
    assert(data.strip() == "success");
    return 0;
# end def


def func_test_json_caa(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_for_test_json_caa.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test_json_lp(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_test_json_lp.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test_json_nid(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_test_json_nid.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def


def func_test_json_a(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_test_json_a.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test_json_l32(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_test_json_l32.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def

def func_test_json_l64(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_test_json_l64.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def


def func_test_json_uri(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_test_json_uri.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def


def func_test_json_srv(data):
    data = json.loads(data)
    real_answer = json.loads(open("{}/json_real_test_json_srv.json".format(DATA_DIR)).read())
    assert(Compare().check(data, real_answer) == NO_DIFF)
    return 0
# end def



