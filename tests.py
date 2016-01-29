import pyremoteboot

prb = pyremoteboot.Client("testing")
print len(prb.gen_client_chal())