import sys
import macho_parse

def main():
	tests = ["AngryBirdsFree"]
	for t in tests:
		print "Running Test: ", t
		data = macho_parse.get_data(t)
		for key, value in data.iteritems():
			print key, len(value)
		print ""
'''
	fd = open(sys.argv[1], "rb")
	data = fd.readlines()
	fd.close()
	apis = []
	for i in range(2, len(data)):
		tmp = data[i].split(" ")
		for j in range(1, len(tmp)):
			if len(tmp[j]) > 1:
				apis.append(tmp[j])
				break

	data = macho_parse.get_data(sys.argv[2], frameworks=False)
	for key, value in data.iteritems():
		papis = data[key]
		if len(papis) > 1:
			for a in papis:
				if a not in apis:
					print a
'''



if __name__ == "__main__":
    main()