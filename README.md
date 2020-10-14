# STFUEDR
Silence EDRs by removing kernel callbacks

Code checks for popular EDR/AV driver names and removes them from PspSetXXXXNotifyRoutine callback array.
Not gonna explain in detail. Everything is greatly explained here: https://www.redcursor.com.au/blog/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10 and here: https://www.youtube.com/watch?v=85H4RvPGIX4
The original exploit code: https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/

![Capture](https://user-images.githubusercontent.com/27059441/96011218-51a47300-0e4b-11eb-8980-5e17e8edafde.PNG)
