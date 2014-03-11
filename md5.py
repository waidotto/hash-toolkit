#!/usr/bin/env python2
import argparse
import sys
import struct

def leftrotate(x, c):
	return ((x << c) | (x >> (32 - c))) & 0xffffffff

def digest(message, length = -1, prev = '0123456789abcdeffedcba9876543210', blocks = 0):
	s = [
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]

	K = [
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

	if len(prev) != 32:
		sys.stderr.write('error: length of --prev must be 32 chars.\n')
		exit(1)
	#a0 = 0x67452301
	#b0 = 0xefcdab89
	#c0 = 0x98badcfe
	#d0 = 0x10325476
	a0 = struct.unpack('>I', struct.pack('<I', int(prev[0:8], 16)))[0]
	b0 = struct.unpack('>I', struct.pack('<I', int(prev[8:16], 16)))[0]
	c0 = struct.unpack('>I', struct.pack('<I', int(prev[16:24], 16)))[0]
	d0 = struct.unpack('>I', struct.pack('<I', int(prev[24:32], 16)))[0]
	print hex(a0)
	print hex(b0)
	print hex(c0)
	print hex(d0)

	if length == -1:
		length = len(message) * 8
	if len(message) < (length - 1) / 8 + 1:
		sys.stderr.write('error: Message is too short(--length is too long).\n')
		exit(1)
	if len(message) > (length - 1) / 8 + 1:
		sys.stderr.write('error: Message is too long(--length is too short).\n')
		exit(1)
	if length % 8 == 0:
		message += '\x80'
	else:
		message = message[:-1] + chr((ord(message[-1]) | (1 << (7 - (length % 8)))) & (0xff << (7 - (length % 8))))
	while len(message) % 64 != 56:
		message += '\x00'
	length += blocks * 512
	message += struct.pack('<Q', length)

	for k in range(len(message) / 64):
		M = []
		for j in range(16):
			M.append(struct.unpack('<I', message[k * 64 + j * 4:k * 64 + j * 4 + 4])[0])
		A = a0
		B = b0
		C = c0
		D = d0
		for i in range(64):
			if(0 <= i < 16):
				F = D ^ (B & (C ^ D))
				g = i
			elif(16 <= i < 32):
				F = C ^ (D & (B ^ C))
				g = (5 * i + 1) % 16
			elif(32 <= i < 48):
				F = B ^ C ^ D
				g = (3 * i + 5) % 16
			elif(48 <= i < 64):
				F = C ^ (B | ((~D) & 0xffffffff))
				g = (7 * i) % 16
			temp = D
			D = C
			C = B
			B = (B + leftrotate((A + F + K[i] + M[g]) & 0xffffffff, s[i])) & 0xffffffff
			A = temp
		a0 = (a0 + A) & 0xffffffff
		b0 = (b0 + B) & 0xffffffff
		c0 = (c0 + C) & 0xffffffff
		d0 = (d0 + D) & 0xffffffff
	return ''.join(['%02x' % ord(x) for x in (struct.pack('<I', a0) + struct.pack('<I', b0) + struct.pack('<I', c0) + struct.pack('<I', d0))])

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Toolkit to calclate bitwise-hash and exploit the hash length extension attack')
	parser.add_argument('--length', '-l', help = 'bitwise message length')
	parser.add_argument('--prev', '-p', help = 'result of previous block process')
	parser.add_argument('--blocks', '-b', help = 'number of already processed blocks')
	parser.add_argument('message', help = 'message to calculate hash')
	args = parser.parse_args()
	c = vars(args).copy()
	for k, v in c.items():
		if v == None or k == 'message':
			del c[k]
		elif k == 'length' or k == 'blocks':
			c[k] = int(c[k], 0)
	print digest(args.message, **c)

