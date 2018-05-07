## KDC

`kdc` is a project

## Dependency

```
PROJECT                          CONSTRAINT     VERSION        REVISION  LATEST   PKGS USED
github.com/btcsuite/btcd         branch master  branch master  675abc5   675abc5  1
github.com/ethereum/go-ethereum  ^1.8.7         v1.8.7         66432f3   v1.8.7   8
github.com/golang/protobuf       ^1.1.0         v1.1.0         b4deda0   v1.1.0   1
golang.org/x/crypto              branch master  branch master  4ec37c6   4ec37c6  1
gopkg.in/mgo.v2                  branch v2      branch v2      3f83fa5   3f83fa5  5
```


## Run example code

A running MongoDB is required to run example

```
go build -o ./example/bin/example ./example
cd example/bin/
./example
```

## Recommended develop environment

1. Visual Studio Code
2. Go support: https://marketplace.visualstudio.com/items?itemName=ms-vscode.Go
3. **Dep** for vendor manage: https://github.com/golang/dep