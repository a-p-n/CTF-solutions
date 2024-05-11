from icecream import ic
from itertools import permutations
from collections import OrderedDict
import numpy as np

test_str = '''Efe kqkbkx czwkf akfs kdkf qzfskf wzdcjtfk
Ieqku kqk akfs ikxj kck akfs wkak ukikukf :Q
Lzfqztk ukdj kqk qe wefe: bkvim{wzbkdki_ckse_kckukx_ukdj_wjuk_kfkbewew_mtzujzfwe}
'''.replace(' ','').replace('_','').replace('{','').replace('}','').replace('\n','').replace(':','').lower()

print(test_str)

all_freq = {}

for i in test_str:
    if i in all_freq:
        all_freq[i] += 1
    else:
        all_freq[i] = 1

print(all_freq)
 
keys = list(all_freq.keys())
values = list(all_freq.values())
sorted_value_index = np.argsort(values)
sorted_dict = {keys[i]: values[i] for i in sorted_value_index}
 

res = dict(reversed(list(sorted_dict.items())))
print(res)
key=[x for x in res.keys()]
print(key)

s='aneitkdrumsglhepyojcwfvzxEq'
ind=[]

for i in s:
    ind.append(i)

test_list=[]

test_str='''Efe kqkbkx czwkf akfs kdkf qzfskf wzdcjtfk
Ieqku kqk akfs ikxj kck akfs wkak ukikukf :Q
Lzfqztk ukdj kqk qe wefe: bkvim{wzbkdki_ckse_kckukx_ukdj_wjuk_kfkbewew_mtzujzfwe}
'''.lower()
for i in test_str:
    test_list.append(i)

f=''

for k in test_list:
    flag=False
    for i,j in zip(key,ind):
        if k==i:
            f+=j
            flag=True
            break
    if flag==False:
        f+=k
            
        
    
print(f)