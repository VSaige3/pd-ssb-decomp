Tkinter application to inspect ssb files.
When opening files, defaults to your phantom dust mod directory.
<Alt-Left> to go back from a jump. Right click on elements to see actions.
Right click on function names to rename them.
At the moment the code cannot recognize functions with multiple returns as one
continuous function. I will probably fix this, so don't get too attached to the names
of these fake functions (currently I've been annotating them by giving them the same name as their parent function but
with a `::descriptor` for readability). You can also rename local variables and
parameters, but note that they only apply from the line you rename them on, in the same function, and cannot be changed
except by editing the symbols file (see the symbols readme).