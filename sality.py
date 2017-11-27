def Word(i):
	return ord(file[i]) | (ord(file[i + 1]) << 8)
def Dword(i):
	return ord(file[i]) | (ord(file[i + 1]) << 8) | (ord(file[i + 2]) << 16) | (ord(file[i + 3]) << 24)

# binary specific values
AMOUNT_TO_DECRYPT = 0x1018 + 0x17E8
XOR_KEY_OFFSET = 0x77
ASCII_XOR = 0x66

sality = "Sality_627B8095B1024A0DDFDFA01BF9AFF803.exe"
ifile = open(sality, 'rb')
file = ifile.read()

if Word(0x00) != 0x5A4D:
	print("Invalid PE file")
	quit()

header = Dword(0x3C)
optional_headers = Word(header + 0x14)
num_sections = Word(header + 0x6)
section_size = 0x28
first_section = header + optional_headers + 0x20
last_section  = header + optional_headers + 0x20 + section_size*(num_sections - 1)

#+0x4 is Virtual Address
#+0xC is Raw Address
first_rva_offset = -Dword(first_section + 0x4) + Dword(first_section + 0xC)

entrypoint = Dword(header + 0x28) + first_rva_offset
src = Dword(last_section + 0xC)
xor_key = Dword(entrypoint + XOR_KEY_OFFSET)

if Dword(entrypoint) != 0x0055E860:
	print("Sality not detected")
	quit()

# decrypt last section in the binary
data = bytearray()
while AMOUNT_TO_DECRYPT > 0:
	word = Word(src)
	src += 2

	xor = (AMOUNT_TO_DECRYPT * xor_key) - (AMOUNT_TO_DECRYPT << 1)
	word ^= xor

	# ascii chars encoded via another XOR
	byte1 = word & 0xFF
	byte2 = (word & 0xFF00) >> 8
	if byte1 != ASCII_XOR and byte1 != 0:
		byte1 ^= ASCII_XOR
	if byte2 != ASCII_XOR and byte2 != 0:
		byte2 ^= ASCII_XOR

	data.append(byte1)
	data.append(byte2)

	AMOUNT_TO_DECRYPT -= 1

# get urls from last section
url = ""
i = data.find('http')
while i != -1:
	while data[i] != 0:
		url += chr(data[i])
		i += 1
	print(url)
	url = ""
	i = data.find('http', i)