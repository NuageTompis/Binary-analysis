# Obtaining the file content
import sys
from struct import *

NUMBER_OF_SECTIONS = 0
ADDRESS_OF_CODE_SECTION = 0
SIZE_OF_CODE_SECTION = 0


def beginSection(sectionName):
    OUTPUT_ARRAY.append(("Section", sectionName))


def endSection():
    OUTPUT_ARRAY.append(("SectionEnd", 0))


if (len(sys.argv) <= 1):
    f_name = "binanalysis.exe"
else:
    f_name = sys.argv[1]


with open(f_name, mode='rb') as f_i:  # b is important -> binary
    f_c = f_i.read()  # file content

# Conversion fonctions


def value(word):
    sum = 0
    for i in range(len(word)-1, -1, -1):
        sum += word[i] * (256**i)
    return (int)(sum)


# The intervals of ascii characters that can be printed
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

# Data structure currently considered

# MS-DOS HEADERS
    # MS-DOS header
    # MS-DOS stub

# PE/COFF HEADERS
    # PE signature
    # PE header
    # PE optional header

###

# Function used to print most of the data structure


def revValue(word):
    sum = 0
    for i in range(len(word)):
        sum += word[i] * (16**(2*i))
    return hex(sum)


def rawValue(word):
    sum = 0
    for i in range(len(word)):
        sum += word[i] * (16**(2*(len(word)-1-i)))
    return hex(sum)


def PRINTER(structure, output, ndx):
    for field in structure:
        # Update NUMBER_OF_SECTIONS
        if (field[0] == "NumberOfSections"):
            global NUMBER_OF_SECTIONS
            NUMBER_OF_SECTIONS = value(f_c[ndx:ndx+field[1]])

        #  If the field is a single value
        if (type(field[1]) == type(1)):
            if (field[2] == 0):
                decoded = str(value(f_c[ndx:ndx+field[1]]))
            elif field[2] == 1:
                decoded = revValue(f_c[ndx:ndx+field[1]])
            else:
                decoded = deciToAscii(f_c[ndx:ndx+field[1]])
            output += "  " + field[0] + " : " + \
                decoded
            OUTPUT_ARRAY.append(
                ["Field", field[0],  revValue(f_c[ndx:ndx+field[1]]), decoded])
            ndx += field[1]
        # If the field is a list of values
        else:
            output += "  " + field[0] + " : "
            overallSizes = 0
            for i in range(len(field[1])):
                overallSizes += field[1][i]
            overallDecoded = ""
            overallHexa = revValue(f_c[ndx:ndx+overallSizes])
            # jsp pk j'avais mis len(field[1])-1 --> ah si c'était pcq je printais les (n-1) premiers suivis d'une virgule et pas le dernier
            for i in range(len(field[1])):
                if (field[2][i] == 0):
                    decoded = str(value(f_c[ndx:ndx + field[1][i]]))
                    output += str(value(f_c[ndx:ndx +
                                  field[1][i]])) + " , "
                elif field[2][i] == 1:
                    decoded = revValue(f_c[ndx:ndx+field[1][i]])
                    output += revValue(f_c[ndx:ndx+field[1][i]]) + " , "
                else:
                    decoded = deciToAscii(f_c[ndx:ndx+field[1][i]])
                    output += deciToAscii(f_c[ndx:ndx+field[1][i]]) + " , "
                overallDecoded += decoded + " , "
                ndx += field[1][i]
            OUTPUT_ARRAY.append(
                ["Field", field[0], overallHexa, overallDecoded])
        output += "\n"
    return output, ndx
##

# 1. MS-DOS HEADERS


# List of each field of the file header and its size in bytes
# The value shall be read as an integer, hexa or an ascii character depending on the 3rd value of the tuple
_IMAGE_DOS_HEADER = [("Magic number", 2, 2),
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
OUTPUT_ARRAY = []
beginSection("MS-DOS Headers")
beginSection("MS-DOS Header")
for count, field in enumerate(_IMAGE_DOS_HEADER):
    if (type(field[1]) == type(1)):
        if (field[2] == 0):
            decoded = str(value(f_c[ndx:ndx+field[1]]))
        elif field[2] == 1:
            decoded = revValue(f_c[ndx:ndx+field[1]])
        else:
            decoded = deciToAscii(f_c[ndx:ndx+field[1]])
        OUTPUT += "  " + field[0] + " : " + \
            decoded
        OUTPUT_ARRAY.append(
            ["Field", field[0],  revValue(f_c[ndx:ndx+field[1]]), decoded])
        ndx += field[1]
    else:
        OUTPUT += "  " + field[0] + " : "
        # compute the sum of the sizes of the fields
        overallSizes = 0
        for i in range(len(field[1])):
            overallSizes += field[1][i]
        overallDecoded = ""
        overallHexa = revValue(f_c[ndx:ndx+overallSizes])
        for i in range(len(field[1])):
            if (field[2][i] == 0):
                decoded = str(value(f_c[ndx:ndx + field[1][i]]))
            elif field[2][i] == 1:
                decoded = revValue(f_c[ndx:ndx+field[1][i]])
            else:
                decoded = deciToAscii(f_c[ndx:ndx+field[1][i]])
            overallDecoded += decoded + " , "
            OUTPUT += decoded + " , "
            ndx += field[1][i]
        OUTPUT_ARRAY.append(["Field", field[0], overallHexa, overallDecoded])
    OUTPUT += "\n"
    if (count == len(_IMAGE_DOS_HEADER)-1):
        addr = value(f_c[ndx-4:ndx])
endSection()

OUTPUT += separator
OUTPUT += " MS-DOS stub :\n"
OUTPUT += "  " + deciToAscii(f_c[ndx:addr]) + "\n"

beginSection("MS-DOS Stub")
OUTPUT_ARRAY.append(
    ("Field", "Stub", revValue(f_c[ndx:addr]), deciToAscii(f_c[ndx:addr])))
endSection()

ndx = addr

# 2. PE/COFF HEADERS

OUTPUT += separator
OUTPUT += separator
OUTPUT += "PE/COFF Headers :\n"
beginSection("PE/COFF Headers")
beginSection("PE signature")
OUTPUT_ARRAY.append(("Field", "Signature", revValue(
    f_c[ndx:ndx+4]), deciToAscii(f_c[ndx:ndx+4])))
endSection()

OUTPUT += separator
OUTPUT += " PE signature :\n"
OUTPUT += "  " + deciToAscii(f_c[ndx:ndx+4]) + "\n"
ndx += 4

_IMAGE_FILE_HEADER = [("Machine", 2, 0),
                      ("NumberOfSections", 2, 0),
                      ("TimeDateStamp", 4, 0),
                      ("PointerToSymbolTable", 4, 0),
                      ("NumberOfSymbols", 4, 0),
                      ("SizeOfOptionalHeader", 2, 0),
                      ("Characteristics", 2, 0)]

OUTPUT += separator
OUTPUT += " PE file header :\n"

beginSection("PE file header")
OUTPUT, ndx = PRINTER(_IMAGE_FILE_HEADER, OUTPUT, ndx)
endSection()

OUTPUT += separator
OUTPUT += " PE optional header :\n"

_IMAGE_OPTIONAL_HEADER = [("Magic", 2, 1),
                          ("MajorLinkerVersion", 1, 0),
                          ("MinorLinkerVersion", 1, 0),
                          ("SizeOfCode", 4, 0),
                          ("SizeOfInitializedData", 4, 0),
                          ("SizeOfUninitializedData", 4, 0),
                          ("AddressOfEntryPoint", 4, 0),
                          ("BaseOfCode", 4, 0),
                          ("BaseOfData", 4, 0),
                          ("ImageBase", 4, 0),
                          ("SectionAlignment", 4, 0),
                          ("FileAlignment", 4, 0),
                          ("MajorOperatingSystemVersion", 2, 0),
                          ("MinorOperatingSystemVersion", 2, 0),
                          ("MajorImageVersion", 2, 0),
                          ("MinorImageVersion", 2, 0),
                          ("MajorSubsystemVersion", 2, 0),
                          ("MinorSubsystemVersion", 2, 0),
                          ("Win32VersionValue", 4, 0),
                          ("SizeOfImage", 4, 0),
                          ("SizeOfHeaders", 4, 0),
                          ("CheckSum", 4, 0),
                          ("Subsystem", 2, 0),
                          ("DllCharacteristics", 2, 0),
                          ("SizeOfStackReserve", 4, 0),
                          ("SizeOfStackCommit", 4, 0),
                          ("SizeOfHeapReserve", 4, 0),
                          ("SizeOfHeapCommit", 4, 0),
                          ("LoaderFlags", 4, 0),
                          ("NumberOfRvaAndSizes", 4, 0),
                          ("DataDirectory", [8 for i in range(16)], [
                              1 for i in range(16)])
                          ]
# DataDirectory n'existe pas en 32 bits ??????? Si...

beginSection("PE optional header")
OUTPUT, ndx = PRINTER(_IMAGE_OPTIONAL_HEADER, OUTPUT, ndx)
endSection()
endSection()

# Writing the output in a file

f_o = open("output.txt", "w")
f_o.write(OUTPUT)

f_i.close()
f_o.close()

f_o_html = open("output.html", "w")
f_o_html.write('<html><head><meta name="viewport"> <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" crossorigin="anonymous"></head><link rel="stylesheet" href="./styles.css " /></head><body style=" width: 100%;  margin: 0px; background-color: rgb(80, 80, 80);"> ')
# Add header
f_o_html.write('<div class="header"><a href="https://github.com/NuageTompis/Binary-analysis" target="_blank"><img src="./images/github-icon-1600.png"  height="50hv" width="50hv" alt="GitHub Icon"/></a><a class="button-link" href="https://gist.github.com/JamesMenetrey/d3f494262bcab48af1d617c3d39f34cf"><button>WinNT.h</button></a><a class="button-link" href="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"><button>BaseTsd.h</button></a></div>')

endSection()

_IMAGE_SECTION_HEADER = [
    ("Name", 8, 2),
    ("VirtualSize", 4, 0),
    ("VirtualAddress", 4, 0),
    ("SizeOfRawData", 4, 0),
    ("PointerToRawData", 4, 0),
    ("PointerToRelocations", 4, 0),
    ("PointerToLinenumbers", 4, 0),
    ("NumberOfRelocations", 2, 0),
    ("NumberOfLinenumbers", 2, 0),
    ("Characteristics", 4, 0),
]
SECTION_SIZE = 0
# compute the sum
for i in range(len(_IMAGE_SECTION_HEADER)):
    SECTION_SIZE += _IMAGE_SECTION_HEADER[i][1]

beginSection("Section headers")
for i in range(NUMBER_OF_SECTIONS):
    sectionName = deciToAscii(f_c[ndx:ndx+_IMAGE_SECTION_HEADER[0][1]])
    beginSection(sectionName)
    for k in range(len(_IMAGE_SECTION_HEADER)):
        if (_IMAGE_SECTION_HEADER[k][2] == 0):
            decoded = str(value(f_c[ndx:ndx+_IMAGE_SECTION_HEADER[k][1]]))
        elif _IMAGE_SECTION_HEADER[k][2] == 1:
            decoded = revValue(
                f_c[ndx:ndx+_IMAGE_SECTION_HEADER[k][1]])
        else:
            decoded = deciToAscii(
                f_c[ndx:ndx+_IMAGE_SECTION_HEADER[k][1]])
        # If the field is the relative index and the section is .text
        if (_IMAGE_SECTION_HEADER[k][0] == "PointerToRawData"):
            if (sectionName == ".text   "):
                ADDRESS_OF_CODE_SECTION = value(
                    f_c[ndx:ndx+_IMAGE_SECTION_HEADER[k][1]])
        # If the field is the section size and the section is .text
        if (_IMAGE_SECTION_HEADER[k][0] == "VirtualSize"):
            if (sectionName == ".text   "):
                SIZE_OF_CODE_SECTION = value(
                    f_c[ndx:ndx+_IMAGE_SECTION_HEADER[k][1]])
        OUTPUT_ARRAY.append(
            ["Field", _IMAGE_SECTION_HEADER[k][0],  revValue(f_c[ndx:ndx+_IMAGE_SECTION_HEADER[k][1]]), decoded])
        ndx += _IMAGE_SECTION_HEADER[k][1]
    endSection()
endSection()

# Write .text section
beginSection(".text")
OUTPUT_ARRAY.append(("Field", "Section .text", rawValue(
    f_c[ADDRESS_OF_CODE_SECTION:ADDRESS_OF_CODE_SECTION+SIZE_OF_CODE_SECTION]), ""))
endSection()

width = 32
for i in range(len(OUTPUT_ARRAY)):
    if (OUTPUT_ARRAY[i][0] == "Section"):
        f_o_html.write('<div class="card" style="width: '+str(width)+'rem;">')
        width -= 4
        f_o_html.write('<h5 class="card-title">'+OUTPUT_ARRAY[i][1]+'</h5>')
        f_o_html.write('<div class="card-body">')
    elif (OUTPUT_ARRAY[i][0] == "SectionEnd"):
        f_o_html.write('</div></div>')
        width += 4
    else:
        f_o_html.write('<p class="card-text">' + '<b>' + OUTPUT_ARRAY[i][1] + '</b>' +
                       '  --  '+OUTPUT_ARRAY[i][2]+'  --  '+OUTPUT_ARRAY[i][3]+'</p>')
# print(OUTPUT_ARRAY)
f_o_html.write(' </body></html>')
f_o_html.close()
