# redis-py exposes two client classes that implement these commands

from _settings import *
import redis
import math
import os
import numpy as np
# The StrictRedis class attempts to adhere to the official command syntax.
db = redis.StrictRedis(host=DB_HOST,port=DB_PORT, db=2, password=DB_PSWD)
#count is used to count the dictionaries
counter = dict()
for i in range(200):
    counter[i] = 0
    print counter
#The Redis SCAN command  is used in order to incrementally iterate over a collection of elements
#HSCAN iterates over the fields in a Hash data structure. 
#The cursor returned it (and all members of the SCAN family), is a number that Redis uses to identify the "position" it stopped at.
cursor = 0
out_list=[] #empty list
for i in range(10000):
    if i % 10 == 0:
        print ("Progress:%d" % i)
    ct = 1000
    if i == 10000:
        ct = 900
    res = db.hscan(name="data_count", cursor=cursor, count=ct)
    #count is the no. of times it counts that is 900
    #data weight calculation
    #Redis HGET command is used to get the value associated with the field in the hash stored at the key.
    cursor = res[0]
    for k in res[1]:
        counter[int(math.log(float(res[1][k]),2))] += 1
        if int(res[1][k]) > 1000:
            anwser = db.hget(name="data_weight", key=k)
            out_list.append((int(anwser),db.hget(name="un_ob_pn", key=k)))

print counter


