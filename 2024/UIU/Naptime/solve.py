a =  [66128, 61158, 36912, 65196, 15611, 45292, 84119, 65338]
ct = [273896, 179019, 273896, 247527, 208558, 227481, 328334, 179019, 336714, 292819, 102108, 208558, 336714, 312723, 158973, 208700, 208700, 163266, 244215, 336714, 312723, 102108, 336714, 142107, 336714, 167446, 251565, 227481, 296857, 336714, 208558, 113681, 251565, 336714, 227481, 158973, 147400, 292819, 289507]

def generate_8bit_binary_values():
    binary_values = []
    for i in range(256):
        binary_value = format(i, '08b')
        binary_values.append(binary_value)
    return binary_values

binary_values = generate_8bit_binary_values()

flag = ['',]*len(ct)
for i in binary_values[1:]:
    f = 0
    for j in range(8):
        if i[j] == '1':
            f += a[j]
    for c in range(len(ct)):
        if f == ct[c]:
            flag[c] = chr(int(i,2))
print(''.join(flag))

