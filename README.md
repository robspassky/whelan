# whelan

This is a python script for dumping http traffic using pylibpcap.

I have a need to know the exact parameters being sent to our servers
from certain devices, without any access to the server logs themselves.
So with whelan I will have those devices hooked up to a network where
I can sniff the traffic and determine the way in which our services
are used.

The python scripts here are the example scripts from the ubuntu
pylibpcap distribution, with some tweaks I'm adding for my use case.
