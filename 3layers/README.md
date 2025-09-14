# buind mkcerts.go
```

CGO_ENABLED=0 GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" -o mkcerts mkcerts.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" mkcerts.go

CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o mkcerts mkcerts.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" mkcerts.go

```
