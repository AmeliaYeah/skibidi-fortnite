# made by Mel

had to use volatility2 in a volatility2 docker container for this specific memory dump extension (end me)
https://github.com/breppo/Volatility-BitLocker

use `imageinfo` to identify the memdump, i got `Win10x64_19041`

`python vol.py -f ../home/python/memdump.mem bitlocker --profile=Win10x64_19041`

for each dumped fvek
`dislocker -k ./skibidi/*.fvek bitlocker-2.dd ./q && mount ./q/dislocker-file ./h`

`0x9e8879926a50-Dislocker.fvek` was the right fvek to decrypt