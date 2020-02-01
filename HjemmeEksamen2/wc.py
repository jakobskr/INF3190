import sys
import os

def wc (filename):
    lines = 0
    words = 0
    chars = 0
    with open(filename) as file:
        for line in file:
            lines += 1
            line = line.split()
            #print(line)
            words += len(line)
            for word in line:
                #print (word, len(word))
                chars += len(word)
        print("%d %d %d %s" % (lines,words, chars, filename))

arr = os.listdir();
if sys.argv[1] == '*':
    arr = os.listdir();
    for file in arr:
        if os.path.isfile(file):
            wc(file)
    #print("wc all files", sys.argv[1:], sys.argv[1])

elif sys.argv[1] == '*.py':
    arr = os.listdir();
    for file in arr:
        if os.path.isfile(file) and file.endswith('.py'):
            wc(file)
else:
    wc(sys.argv[1])

#print(arr)

#wc(sys.argv[1])
#print(sys.argv[1:])
