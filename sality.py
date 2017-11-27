def Word(i):
	return ord(file[i]) | (ord(file[i + 1]) << 8)
def Dword(i):
	return ord(file[i]) | (ord(file[i + 1]) << 8) | (ord(file[i + 2]) << 16) | (ord(file[i + 3]) << 24)

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

first_rva_offset = -Dword(first_section + 0x4) + Dword(first_section + 0xC)
last_rva_offset  = -Dword(last_section + 0x4) + Dword(last_section + 0xC)

entrypoint = Dword(header + 0x28) + first_rva_offset

src = entrypoint - first_rva_offset + Dword(entrypoint + 0xD) + last_rva_offset
counter = 0x1018 + 0x17E8
xor_key = Dword(entrypoint + 0x77)

if Dword(entrypoint) != 0x0055E860:
	print("Sality not detected")
	quit()

# decrypt last section in the binary
data = bytearray()
while counter > 0:
	word = Word(src)
	src += 2

	xor = (counter * xor_key) - (counter << 1)
	word ^= xor
	data.append(word & 0xFF)
	data.append((word & 0xFF00) >> 8)

	word = xor
	counter -= 1

# get urls from last section
url = ""
addr = 0x626
while data[addr] != 0xFF:
	while data[addr] != 0:
		if data[addr] != 0x66:
			url += chr(data[addr] ^ 0x66)
		else:
			url += chr(0x66)
		addr += 1
	addr += 1
	#url += idc.GetString(0x1000F010) + "&rnd="
	print(url)
	url = ""
