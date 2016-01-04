import pyremoteboot

prb = pyremoteboot.Client("testing")
print prb._gen_client_chal()