# buind mkcerts.go
```
# linux
CGO_ENABLED=0 GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" -o mkcerts mkcerts.go
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o mkcerts mkcerts.go

# windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" -o mkcerts.exe mkcerts.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o mkcerts.exe mkcerts.go

```
