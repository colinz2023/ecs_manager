_VERSION=V1.0.1
_DATE=$(shell date +"%Y%m%d")
BUILD_DIR = build
SQLITECPP_SRC_DIR = db/sqlite_cpp
SQLITECPP_SRC = $(wildcard $(SQLITECPP_SRC_DIR)/*.cpp)
SQLITECPP_OBJS = $(patsubst %.cpp, $(BUILD_DIR)/%.o, $(notdir $(SQLITECPP_SRC)))
SQLITE_SRC_DIR = db/sqlite
SQLITE_SRC = $(SQLITE_SRC_DIR)/sqlite3.c
SQLITE_OBJS = $(patsubst %.c, $(BUILD_DIR)/%.o, $(notdir $(SQLITE_SRC)))

ECS_MANAGER_SRC =  ecs_manager_cli.cc ecs_db.cc ecs_manager.cc cmdline.cc 
ECS_MANAGER_OBJS = $(patsubst %.cc, $(BUILD_DIR)/%.o, $(notdir $(ECS_MANAGER_SRC)))

SSH_TOOL_SRC = ssh_tool.cc
SSH_TOOL_OBJS = $(patsubst %.cc, $(BUILD_DIR)/%.o, $(notdir $(SSH_TOOL_SRC)))

COMMON_SRC = utils.cc ssh2.cc
COMMON_OBJS = $(patsubst %.cc, $(BUILD_DIR)/%.o, $(notdir $(COMMON_SRC)))


CCFLAGS = -I $(SQLITE_SRC_DIR) -I $(SQLITECPP_SRC_DIR) -I. -DECSM_TOOL_VERSION="\"$(_VERSION)\""
CCLDFLAGS = -L.

ifdef static
ECSM_LIBS = -lssh2 -lgcrypt -lgpg-error -lz -lpthread -ldl
SSH_LIBS = -lssh2 -lgcrypt -lgpg-error -lz -lpthread
ECSM_STATIC = -static
STATIC_FLAG = static
else
ECSM_LIBS = -lssh2 -lpthread -ldl
SSH_LIBS = -lssh2 -lpthread
ECSM_STATIC = 
STATIC_FLAG =
endif

ifdef ssh_static
ECSM_LIBS = -Wl,-dn -lssh2 -lgcrypt -lgpg-error -lz  -Wl,-dy -ldl -lpthread
SSH_LIBS = -Wl,-dn -lssh2 -lgcrypt -lgpg-error -lz  -Wl,-dy -lpthread
ECSM_STATIC = 
STATIC_FLAG =
endif

all:build_dir sqlitecpp.a ssh_tool ecs_import_db ecs_tool 

build_dir:$(BUILD_DIR)
	@test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)

sqlitecpp.a:$(SQLITECPP_OBJS) $(SQLITE_OBJS)
	$(AR) -cvr sqlitecpp.a $^

ssh_cli:$(ECS_MANAGER_OBJS) $(COMMON_OBJS)
	$(CXX) $^ $(CCLDFLAGS) -l:sqlitecpp.a -l:libgflags.a -lssh2 -lpthread -ldl  -o $@ 

ecs_tool:$(COMMON_OBJS) ecs_db.cc ecs_manager.cc ecs_tool.cc
	$(CXX) $^ $(CCFLAGS) $(CCLDFLAGS) -l:sqlitecpp.a  $(ECSM_STATIC) $(ECSM_LIBS) -o $@

ssh_tool:$(SSH_TOOL_OBJS) $(COMMON_OBJS)
	$(CXX) $^ $(CCFLAGS) $(ECSM_STATIC) $(SSH_LIBS) -o $@

ecs_import_db:ecs_import_db.cc ecs_db.cc utils.cc
	$(CXX) $^ $(CCLDFLAGS) $(CCFLAGS) -l:sqlitecpp.a $(ECSM_STATIC) $(ECSM_LIBS) -o $@ 

test:ssh2_test db_test

ssh2_test:test/ssh2_test.cc ssh2.cc
	$(CXX) $^ -I. -lssh2  -o $@

db_test:test/db_test.cc sqlitecpp.a
	$(CXX) $^ -I. -ldl -lpthread -o $@

$(SQLITECPP_OBJS):$(BUILD_DIR)/%.o:$(SQLITECPP_SRC_DIR)/%.cpp
	$(CXX) -o $@ -c $< $(CCFLAGS)

$(SQLITE_OBJS):$(BUILD_DIR)/%.o:$(SQLITE_SRC_DIR)/%.c
	$(CC) -o $@ -c $< -I. -DSQLITE_THREADSAFE=2

$(ECS_MANAGER_OBJS):$(BUILD_DIR)/%.o:./%.cc
	$(CXX) -o $@ -c $< $(CCFLAGS) -Wall

$(SSH_TOOL_OBJS):$(BUILD_DIR)/%.o:./%.cc
	$(CXX) -o $@ -c $< -I. -Wall

$(COMMON_OBJS):$(BUILD_DIR)/%.o:./%.cc
	$(CXX) -o $@ -c $< -I. -Wall

tar:
	md5sum eu.db ssh_tool ecs_tool ecm_import_db   > CHEAK
	tar -czvf ecs_cli_$(_VERSION)_$(STATIC_FLAG)_$(_DATE).tar.gz CHEAK README ssh_tool ecs_tool ecs_import_db 
zip:
	md5sum ssh_tool ecs_tool ecs_import_db  > CHEAK
	zip --password Colin@123 ecs_cli_$(_VERSION)_$(STATIC_FLAG)_$(_DATE).zip CHEAK README ssh_tool ecs_tool ecs_import_db

build:
	mkdir build

clean:
	rm -f ssh_tool ecs_cli sqlitecpp.a ecs_manager_cli ecs_import_db ecs_tool
	rm -f $(SQLITE_OBJS) $(SQLITECPP_OBJS) $(ECS_MANAGER_OBJS) $(SSH_TOOL_OBJS) $(COMMON_OBJS)
.PHONY: all clean test
