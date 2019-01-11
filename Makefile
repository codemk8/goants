ifndef $(tag)
	tag=latest
endif

build: cmd/*/*.go
	GOOS=linux go build -o bin/auth.exe codemk8/goants/cmd/main
	chmod +x bin/auth.exe	

test:
	go test codemk8/goants/cmd/pkg

clean:
	-rm -rf bin
