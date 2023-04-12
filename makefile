MAIN_FILE = main.go
OUTPUT = portScanner.exe

build:
	go build -o ${OUTPUT} ${MAIN_FILE}
	
run:
	go run main.go --addr github.com --ports 0-65535