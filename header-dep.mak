%.o: %.c
	$(COMPILE.c) -MMD -MP $< -o $@

srcs = $(wildcard *.c)
deps = $(srcs:.c=.d)

-include $(deps)
