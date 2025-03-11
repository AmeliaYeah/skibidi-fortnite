jules

the hint says to use frida
desc talks about waking up the program, maybe the program using some sort of Sleep function
it says its using the windows API

frida‑trace -i "Sleep" -f ./bininst1.exe 
-i "Sleep" tells it to only trace calls to the Sleep function
-f tells it to spawn the process instead of attaching to an already running process

then we do
frida -l eepy_cat_waking.js -f ./bininst1.exe



this runs the exe and intercepts calls to a function named Sleep
in the output, we see its called from KERNEL32.dll and KERNELBASE.dll
frida logs the call and generates some js code, it juts logs it
we can override Sleep's behavior with our own script
we know the target function Sleep is located in KERNEL32.dll and KERNELBASE.dll


eeepy_cat_waking.js lets us override the Sleep function
-l tells frida to load the script (i think)