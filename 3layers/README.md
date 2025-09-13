# buind mkcerts.go
```
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o mkcerts mkcerts.go
```
