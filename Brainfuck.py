import sys

# In case you done goof
class CompileExcpetion(Exception):
	pass
class RuntimeException(Exception):
	pass

def BrainFuck(code):
	# strip all of the non executable characters
	code = ''.join(c for c in code if c in '<>,.+-[]')

	# make sure while loops are correct
	braceCount = 0
	loop_stack = [] # queue for while loop jump 'pointers'
	loop_lookup = {} # dictionary to store the while loop jumps
	for x in range(len(code)):
		if code[x] == '[':
			braceCount += 1
			loop_stack.append(x)
		elif code[x] == ']':
			braceCount -= 1
			# all looping pointers are stored in this dictionary.
			# since python dictionaries are O(1), this is the easiest opition
			start = loop_stack.pop()
			loop_lookup[x] = start - 1
			loop_lookup[start] = x
		if braceCount < 0:
			raise CompileExcpetion("ERROR: Miss matched braces.")
	if braceCount != 0:
		raise CompileExcpetion("ERROR: Expected another ] somewhere.")

	# Alright, lets start the actual program
	memory = [0]*30000 # as defined by Urban Meuller, the dude who made BrainFuck
	mem_ptr = 0 # points to current block of memory
	code_ptr = 0 # points to current executable byte

	while(code_ptr != len(code)):
		# increment block
		if code[code_ptr] == '+':
			memory[mem_ptr] += 1
			if memory[mem_ptr] >= 256:
				raise RuntimeException("Integer Overflow")
		# decrement block
		elif code[code_ptr] == '-':
			memory[mem_ptr] -= 1
			if memory[mem_ptr] < 0:
				raise RuntimeException("Integer Underflow")
		# move pointer one block to the right
		elif code[code_ptr] == '>':
			mem_ptr += 1
			if mem_ptr > 30000:
				raise RuntimeException("Over memory bounds")
		# move pointer one block to the left
		elif code[code_ptr] == '<':
			mem_ptr -= 1
			if mem_ptr < 0:
				raise RuntimeException("Under memory bounds")
		# write character
		elif code[code_ptr] == '.':
			sys.stdout.write(chr(memory[mem_ptr]))
		# read character
		elif code[code_ptr] == ',':
			memory[mem_ptr] = ord(sys.stdin.read(1))
		# loop start
		elif code[code_ptr] == '[':
			if memory[mem_ptr] == 0:
				code_ptr = loop_lookup[code_ptr]
		# loop ending
		elif code[code_ptr] == ']':
			code_ptr = loop_lookup[code_ptr]
		code_ptr += 1


def brainfuck_decode(code):
    # 初始化内存和指针
    memory = [0] * 30000
    pointer = 0

    # 结果字符串
    result = ""

    # 循环遍历 Brainfuck 代码
    i = 0
    while i < len(code):
        char = code[i]

        if char == '>':
            pointer += 1
        elif char == '<':
            pointer -= 1
        elif char == '+':
            memory[pointer] += 1
        elif char == '-':
            memory[pointer] -= 1
        elif char == '.':
            result += chr(memory[pointer])
        elif char == ',':
            # 这里需要实现读取用户输入的逻辑
            pass
        elif char == '[':
            # 如果当前指针所在的内存位置为0，则跳转到与之对应的"]"之后
            if memory[pointer] == 0:
                loop_count = 1
                while loop_count > 0:
                    i += 1
                    if code[i] == '[':
                        loop_count += 1
                    elif code[i] == ']':
                        loop_count -= 1
            else:
                # 否则继续执行下面的指令
                pass
        elif char == ']':
            # 如果当前指针所在的内存位置不为0，则跳转到与之对应的"["之前
            if memory[pointer] != 0:
                loop_count = 1
                while loop_count > 0:
                    i -= 1
                    if code[i] == ']':
                        loop_count += 1
                    elif code[i] == '[':
                        loop_count -= 1
                # 因为循环结束后还会+1，所以这里需要减去1
                i -= 1
            else:
                # 否则继续执行下面的指令
                pass

        i += 1

    return result


brainfuck_code = "++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------."
decoded_string = brainfuck_decode(brainfuck_code)
print("Brainfuck解码后：" + decoded_string)
