How to Run the program:
	You might have to attempt starting the more than one time due to unbinding some of the sockpaths. It shouldn’t happen, but it might.
The easiest way to compile is to use the supplied makefile.  
	make daemon  
	make miptp
	make filec 
	make files
	make ruter
and to run the program you can use the following commands:
./daemon [-h] [-d] <socket_application>  <routing_socket> <forward_socket> [mip_adresses]  
./miptp  [-d] <MIPD_PATH> <MIPTP_PATH> <TIME_OUT>
./filec <FILE NAME> <MIPTP_PATH> <MIP ADDR> <PORT>
./files < MIPTP_PATH > <PORT>
./ruter [-h] <routing_socket> <forward_socket>
NB: mip_addresses must be in the range of 1-254.  
NB: the help command does not execute the program, but only prints the help text. NBB: only mipdaemon and ruter has help print.

Start it in this order :

	mipdaemon
	ruter
	miptp
	then either filec or files