# STFUEDR
Silence EDRs by removing kernel callbacks

Code checks for popular EDR/AV driver names and removes them from PspSetXXXXNotifyRoutine callback array.
Not gonna explain in detail. Everything is already greatly explained

here: https://www.redcursor.com.au/blog/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10  and

here: https://www.youtube.com/watch?v=85H4RvPGIX4

The original exploit code: https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/

![](png/stfuedr.png)
