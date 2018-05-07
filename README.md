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

A running MongoDB is required to run example. The following command shoud be run inside your [GOPATH](https://github.com/golang/go/wiki/GOPATH)

```
git clone https://github.com/GenaroNetwork/KDC_HUST_Genaro.git genaro-crypto
cd genaro-crypto
go build -o ./example/bin/example ./example
cd example/bin/
./example
```

## Recommended develop environment

1. Visual Studio Code
2. [Go support](https://marketplace.visualstudio.com/items?itemName=ms-vscode.Go) for Visual Studio Code
3. [**Dep**](https://github.com/golang/dep) for vendor manage