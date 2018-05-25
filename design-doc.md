UserA 存数据 JSON1 的步骤
1. UserA 生成会话密钥 PK_A1，SK_A1，生成随机数 RND1
2. UserA 将随机数 RND1、对RND1的签名，密钥 PK_A1（可选的 WhiteList1 ）发送给 KDC
3. KDC 根据 RND1 的签名生成文件ID FileID1，生成文件加密密钥 KeyFile1 并用 PK_A1 加密得到 EncryptedKeyFile1，将 WhiteList1（如果有）和 FileID1 关联，持久化存储至权限表 KDC_AC。将 FileID1，EncryptedKeyFile1 返回给 UserA。TODO：bai名单格式
4. UserA 用 SK_A1 解密，获得文件ID以及加密密钥，FileID1，KeyFile1
5. UserA 将文件 JSON1 里面的 key/value 用 KeyFile1 加密，形成 EncryptedJSON1 文件（加密后的k-v对变成了searchablecipher-keycipher-valuecipher三个关联的字符串，具体用什么格式待定）
6. UserA 将文件 EncryptedJSON1 以 FileID1 作为文件名，附上权限表 AC1（格式，内容？）存储至 GenaroNetwork（链 or 存储？其他人根据fileid能获取到？）


UserB 修改 JSON1 数据
1. UserB 事先知道了他要改的 FileID1 以及 JSON 文件里面要改的 JsonKey1（如何知道？）
2. UserB 生成会话密钥 PK_B1，SK_B1
3. UserB 将 FileID1，PK_B1 发给 KDC
4. KDC 通过权限表 KDC_AC 判断 PK_B1 是否拥有权限。如果没有，返回错误。如果有生成文件加密密钥 KeyFile2 并用 PK_B1 加密得到 EncryptedKeyFile2，同时持久化存储 KeyFile2 至权限表 KDC_AC，返回给 UserB EncryptedKeyFile2
5. UserB 用 SK_B1 解密 EncryptedKeyFile2 得到 KeyFile2
6. UserB 将自己的改动 Modify0（如何表示？）用 KeyFile2 加密成 EncryptedModify0，以 FileID1 作为文件名存储至 GenaroNetwork（链 or 存储？）


UserA 获取文件最终状态（通过查询某个key）
1. UserA 向 KDC 请求改动的文件密钥对应用户公钥集合 Key-PK{}，提供的数据是 FileID1，KDC 返回 Key-PK{}
2. UserA 希望获得 JSON 文档里面的 Key 为 Key1 所对应的值 Value1，UserA 在本地使用 Key-PK{} 和 Key1 进行计算，得到一个 token{} 集合
3. UserA 向 GenaroNetwork 提交陷门集合 token{} 和 FileID1，得到文件的加密的初始值 EncryptedJSON1，以及日后的加密的改动集合 {EncryptedModify0，EncryptedModify1，EncryptedModify2…}
4. UserA 通过解密密钥解密文件初始值 Value0 以及改动的集合 Mod-PK{} 
5. UserA 根据 AC1 过滤掉 Mod-PK{} 中的非法的改动
6. UserA 通过初始值 Value0 以及 Mod-PK{} 合法的改动计算得出最终值 ValueN



