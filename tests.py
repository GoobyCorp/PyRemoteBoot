import pyremoteboot

prb = pyremoteboot.Client("testing")
print len(prb._gen_client_chal())