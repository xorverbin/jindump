# 컴파일러 설정
CXX = g++
CXXFLAGS = -Wall -O2 -std=c++14

# 라이브러리 설정
LIBS = -lpcap

# 타겟 설정
TARGET = jindump

# 소스 파일
SRCS = jindump.cpp    

# 오브젝트 파일
OBJS = $(SRCS:.cpp=.o)

# 기본 타겟
all: $(TARGET)

# 링킹
$(TARGET): $(OBJS)
        $(CXX) $(OBJS) -o $(TARGET) $(LIBS)

# 컴파일
%.o: %.cpp
        $(CXX) $(CXXFLAGS) -c $< -o $@

# clean 명령어
clean:
        rm -f $(OBJS) $(TARGET)

# PHONY 타겟
.PHONY: all clean
