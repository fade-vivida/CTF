import os
from PIL import Image

def main():
	png_dir = 'out/'
	ret = ''
	for i in range(24):
		line = ''
		for j in range(24):
			fime_name = png_dir + 'out-' + str(i*24+j) + '.png'
			x = j*10
			y = i*10
			img = Image.open(fime_name)
			img = img.convert("RGB")
			img_array = img.load()
			r,g,b =  img_array[x,y]
			#print r,g,b
			if (r == 0xff) and (b == 0xff):
				line += '1'
			elif g == 0xff:
				line += '0'
			if len(line) == 8:
				ret += chr(int(line,2))
				line = ''
	return ret

if __name__ == '__main__':
	a = main()

