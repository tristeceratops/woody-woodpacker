CC = cc
CC_FLAG = -Wall -Wextra -Werror -Iincludes
BIN = woody_woodpacker
SRC_FILES = main.c utils/ft_memcpy.c
SRC_DIR = ./srcs/
OBJ_DIR = ./objs/
SRCS = $(addprefix $(SRC_DIR), $(SRC_FILES))
OBJS = $(addprefix $(OBJ_DIR), $(SRC_FILES:.c=.o))

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CC_FLAG) -o $(BIN) $(OBJS)

$(OBJ_DIR)%.o: $(SRC_DIR)%.c
	@mkdir -p $(@D)
	$(CC) $(CC_FLAG) -c $< -o $@

clean:
	@rm -rf $(OBJ_DIR)

fclean: clean
	@rm -f $(BIN)

re: fclean all

.PHONY: all clean fclean re