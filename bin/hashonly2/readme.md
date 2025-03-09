# made by Mel

when we interact with the binary, it runs the `md5sum` command. however, if we modify the path by doing
	`export PATH=/home/ctf-player:$PATH`

and then run
	`cp /bin/cat /home/ctf-player/md5sum`

when we run the binary, it'll use this path variable and index the `md5sum` in our directory first, which is `/bin/cat`.

aka: we make the program run `cat flag.txt` instead of `md5sum flag.txt`, and thus get the flag