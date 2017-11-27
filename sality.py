def Word(i):
	return ord(file[i]) | (ord(file[i + 1]) << 8)
def Dword(i):
	return ord(file[i]) | (ord(file[i + 1]) << 8) | (ord(file[i + 2]) << 16) | (ord(file[i + 3]) << 24)

# binary specific values
XOR_KEY_OFFSET = 0x77
ASCII_XOR = 0x66

sality = "Sality_627B8095B1024A0DDFDFA01BF9AFF803.exe"
ifile = open(sality, "rb")
file = ifile.read()
ifile.close

if Word(0x00) != 0x5A4D:
	print("Invalid PE file")
	quit()

header = Dword(0x3C)
optional_headers = Word(header + 0x14)
num_sections = Word(header + 0x6)
section_size = 0x28
first_section = header + optional_headers + 0x20
last_section  = first_section + section_size*(num_sections - 1)

#+0x4 is Virtual Address
#+0x8 is Raw Size
#+0xC is Raw Address
first_section_virt = Dword(first_section + 0x4)
first_section_phys = Dword(first_section + 0xC)
last_section_size  = Dword(last_section + 0x8)
last_section_phys  = Dword(last_section + 0xC)

entrypoint = Dword(header + 0x28) - first_section_virt + first_section_phys
src = last_section_phys						# location to decrypt (last section)
words_to_decrypt = last_section_size / 2	# number of words to decrypt
xor_key = Dword(entrypoint + XOR_KEY_OFFSET)		

# sality begins with PUSHA, CALL+0x55
if Dword(entrypoint) != 0x0055E860:
	print("Sality not detected")
	quit()

# decrypt last section in the binary
data = bytearray()
while words_to_decrypt > 0:
	word = Word(src)
	src += 2

	xor = (words_to_decrypt * xor_key) - (words_to_decrypt << 1)
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

	words_to_decrypt -= 1

# get urls from last section
url = ""
i = data.find("http")
while i != -1:
	while data[i] != 0:
		url += chr(data[i])
		i += 1
	print(url)
	url = ""
	i = data.find("http", i)