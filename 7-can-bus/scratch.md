Signals Ids
080,
188,

# control
019,steering
080,break - secondary signal which is some opposite of the primary signal. all FFs
	Ranges from 0x0-64.
	Can remove via the less than filter

# reporting
244,RPMs

# power
02A, 00FF - Off
02A, FF00 - On

# extra
19B - Locks
Additiona 19B stuff

Unknown Signals
19B 00 00 00 0F 20 57	--ping like remove with an =='s filter
188 00 00 00 00 00 00	--streaming remove with an all match filter
080 00 00 00 00 00 64	--remove with a less than filter for the shadow signal 
						--after looking at the decimal values, the small number is the true value
						--while the big values are actually signed ints and negative which are the
						--malicious signal in the system.