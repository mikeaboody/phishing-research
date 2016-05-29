import sys

######################### INSTRUCTIONS #########################
# 1. To run: python evalOracle.py
# 2. When it says "Enter Line", put the line to be evaluated
# 3. The headers (a list of tuples) will be returned if the 
#    eval() was successful. False will be returned if the line 
#    was not able to be eval()'ed properly.
################################################################

line = raw_input("Enter Line: ")

def evalOracle(line):
	try:
		line = eval(line)
		return line
	except Exception as e:
		print(e)
		return False

print(evalOracle(line))