# made by Mel

run `bitlocker2john bitlocker-1.dd` to get a john the ripper hash of the bitlocker password. many versions are present, i just chose one
	JtR hash: `$bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$12$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b2999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d71ba31b6779c6f41412fd6869442d66d`
	password obtained from `rockyou.txt` wordlist: `jacqueline`

make a mountpoint, then do `sudo dislocker file -u mount_pt`. specify the user password, then mount the `dislocker-file` into another directory to access the file system and the `flag.txt`