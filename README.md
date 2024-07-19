It is meant to be a quick project to learn how to bypass AMSI by hooking the export address table(EAT) of Powershell. There is not alot about EAT hooking other than closed game-hacking forums, but this article explained how to do it successfully - hooking the EAT is different than the IAT : https://www.codereversing.com/archives/598 .

All in all, this was a great learning experince. I learned that AMSI is not imported but loaded dynamically and learned how to hook the EAT of a DLL using this method.
