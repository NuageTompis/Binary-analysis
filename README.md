# Binary-analysis
Project aiming at analyzing a binary file on the Portable Executable (PE) format.

# Usage

`python3 Inspector.py binanalysis.exe`

You may replace `binanalysis.exe` by any PE file you may have placed inside the outmost folder, althought this project is currently only suited for files written for 32-bit-word architecture machines.

This will write the output of the analysis within a new file called output.html, that you may open with the browser of your choice.

# Ressources
[WinNT.h](https://gist.github.com/JamesMenetrey/d3f494262bcab48af1d617c3d39f34cf)
[BaseTsd.h](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
