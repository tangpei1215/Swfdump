Swfdump
=======
Simple swf file dump utility for Linux (requires Python 3.2). Scans memory areas of the
specified process and dumps found files in working directory.

Usage examples
==============
Dump all swf files found in memory of a process specified by PID (1308):

        $ ./swfdump.py 1308
	
Dump files inside of "swf" directory:

        $ ./swfdump.py --dir swf 1308
	
Dump only files larger than 500KB and smaller than 1000KB inside of swf directory:

        $ ./swfdump.py --dir swf --min-size 500 --max-size 1000 1308