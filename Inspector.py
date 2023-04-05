### Obtaining the file content

import sys
from struct import *

if(len(sys.argv)<=1) :
    f_name = "binanalysis.exe"
else:
    f_name = sys.argv[1]


with open(f_name, mode='rb') as f_i: # b is important -> binary
    f_c = f_i.read() # file content

### Conversion fonctions
def value(word):
    sum = 0
    for i in range(len(word)):
        sum += word[i] * (16**i)
    return (int)(sum)

bounds_a = [33, 126]
bounds_b = [161, 255]
def valid(deci):
    if deci >= bounds_a[0] and deci <= bounds_a[1]:
        return True
    # elif deci >= bounds_b[0] and deci <= bounds_b[1]:
    #     return True
    return False

def deciToAscii(deci):
    decoded = ""
    for i in range(len(deci)):
        if valid(deci[i]):
            decoded += chr(int(deci[i]))
        else:
            decoded += " "
    return decoded

### Data structure currently considered

# MS-DOS HEADERS
    # MS-DOS header
    # MS-DOS stub

# PE/COFF HEADERS
    # PE signature
    # PE header
    # PE optional header

###

## Function used to print most of the data structure
def PRINTER(structure,output,ndx) :
    for field in structure:
        # print(field[0])
        if (type(field[1]) == type(1)):
            # print(ndx,ndx+2*field[1],f_c[ndx:ndx+2*field[1]])
            if (field[2] == 0):
                output += "  " + field[0] + " : " + \
                    str(value(f_c[ndx:ndx+field[1]]))
            else:
                output += "  " + field[0] + " : " + \
                    deciToAscii(f_c[ndx:ndx+field[1]])
            ndx += field[1]
        else:
            output += "  " + field[0] + " : "
            for i in range(len(field[1])-1):
                if (field[2][i] == 0):
                    output += str(value(f_c[ndx:ndx +
                                  field[1][i]])) + " , "
                else:
                    output += deciToAscii(f_c[ndx:ndx+field[1][i]]) + " , "
                ndx += field[1][i]
            if (field[2][len(field[1])-1] == 0):
                output += str(value(f_c[ndx:ndx +
                              field[1][len(field[1])-1]]))
            else:
                output += deciToAscii(f_c[ndx:ndx+field[1][len(field[1])-1]])
            ndx += field[1][len(field[1])-1]
        output += "\n"
    return output,ndx
##

##### 1. MS-DOS HEADERS

# List of each field of the file header and its size in bytes
# The value shall be read as an integer or an ascii character depending on the 3rd value of the tuple
_IMAGE_DOS_HEADER = [("Magic number", 2, 1),
                     ("Bytes on last page of file", 2, 0),
                     ("Pages in file", 2, 0),
                     ("Relocations", 2, 0),
                     ("Size of header in paragraphs", 2, 0),
                     ("Minimum extra paragraphs needed", 2, 0),
                     ("Maximum extra paragraphs needed", 2, 0),
                     ("Initial (relative) SS value", 2, 0),
                     ("Initial SP value", 2, 0),
                     ("Checksum", 2, 0),
                     ("Initial IP value", 2, 0),
                     ("Initial (relative) CS value", 2, 0),
                     ("File address of relocation table", 2, 0),
                     ("Overlay number", 2, 0),
                     ("Reserved words", [2 for i in range(4)], [
                      1 for i in range(4)]),
                     ("OEM identifier (for e_oeminfo)", 2, 0),
                     ("OEM information; e_oemid specific", 2, 0),
                     ("Reserved words", [2 for i in range(10)], [
                      1 for i in range(10)]),
                     ("File address of new exe header", 4, 0)]

separator = " ________\n"
OUTPUT = ""

addr = 0  # Relative address of the PE/COFF Headers (given by e_lfanew)
OUTPUT += "MS-DOS HEADERs :\n"
OUTPUT += separator
OUTPUT += " MS-DOS header :\n"
# The index at which we will read the next field in the binary
ndx = 0
for count, field in enumerate(_IMAGE_DOS_HEADER):
    if (type(field[1]) == type(1)):
        if (field[2] == 0):
            OUTPUT += "  " + field[0] + " : " + str(value(f_c[ndx:ndx+field[1]]))
        else:
            OUTPUT += "  " + field[0] + " : " + deciToAscii(f_c[ndx:ndx+field[1]])
        ndx += field[1]
    else:
        OUTPUT += "  " + field[0] + " : "
        for i in range(len(field[1])-1):
            if (field[2][i] == 0):
                OUTPUT += str(value(f_c[ndx:ndx + field[1][i]])) + " , "
            else:
                OUTPUT += deciToAscii(f_c[ndx:ndx+field[1][i]]) + " , "
            ndx += field[1][i]
        if (field[2][len(field[1])-1] == 0):
            OUTPUT += str(value(f_c[ndx:ndx + field[1][len(field[1])-1]]))
        else:
            OUTPUT += deciToAscii(f_c[ndx:ndx+field[1][len(field[1])-1]])
        ndx += field[1][len(field[1])-1]
    OUTPUT += "\n"
    if (count == len(_IMAGE_DOS_HEADER)-1):
        addr = value(f_c[ndx-4:ndx])

OUTPUT += separator
OUTPUT += " MS-DOS stub :\n"
OUTPUT += "  " + deciToAscii(f_c[ndx:addr]) + "\n"

ndx = addr

##### 2. PE/COFF HEADERS

OUTPUT += separator
OUTPUT += separator
OUTPUT += "PE/COFF HEADERs :\n"

OUTPUT += separator
OUTPUT += " PE signature :\n"
OUTPUT += "  " + deciToAscii(f_c[ndx:ndx+4]) + "\n"
ndx += 4

_IMAGE_FILE_HEADER = [("Machine",2,0),
    ("NumberOfSections",2,0),
    ("TimeDateStamp",4,0),
    ("PointerToSymbolTable",4,0),
    ("NumberOfSymbols",4,0),
    ("SizeOfOptionalHeader",2,0),
    ("Characteristics",2,0)]

OUTPUT += separator
OUTPUT += " PE file header :\n"

OUTPUT,ndx = PRINTER(_IMAGE_FILE_HEADER, OUTPUT,ndx)

OUTPUT += separator
OUTPUT += " PE optional header :\n"

_IMAGE_OPTIONAL_HEADER = [("Magic",2,0),
("MajorLinkerVersion",1,0),
("MinorLinkerVersion",1,0),
("SizeOfCode",4,0),
("SizeOfInitializedData",4,0),
("SizeOfUninitializedData",4,0),
("AddressOfEntryPoint",4,0),
("BaseOfCode",4,0),
("BaseOfData",4,0),
("ImageBase",4,0),
("SectionAlignment",4,0),
("FileAlignment",4,0),
("MajorOperatingSystemVersion",2,0),
("MinorOperatingSystemVersion",2,0),
("MajorImageVersion",2,0),
("MinorImageVersion",2,0),
("MajorSubsystemVersion",2,0),
("MinorSubsystemVersion",2,0),
("Win32VersionValue",4,0),
("SizeOfImage",4,0),
("SizeOfHeaders",4,0),
("CheckSum",4,0),
("Subsystem",2,0),
("DllCharacteristics",2,0),
("SizeOfStackReserve",4,0),
("SizeOfStackCommit",4,0),
("SizeOfHeapReserve",4,0),
("SizeOfHeapCommit",4,0),
("LoaderFlags",4,0),
("NumberOfRvaAndSizes",4,0)]

OUTPUT,ndx = PRINTER(_IMAGE_OPTIONAL_HEADER, OUTPUT,ndx)

### Writing the output in a file

f_o = open("output.txt", "w")
f_o.write(OUTPUT)

f_i.close()
f_o.close()
