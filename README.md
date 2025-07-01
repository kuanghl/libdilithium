#### Reference.

- [PQClean](https://github.com/PQClean/PQClean.git): C99实现的官方后量子加密库集合。
- [dilithium](https://github.com/pq-crystals/dilithium.git): liboqs的ml-dsa签名算法引用来源，参考[CRYSTALS-Dilithium](https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/sig/dilithium.md)。
- [RISC-V-SoC](https://github.com/Acccrypto/RISC-V-SoC): 一些基于RISC-V的格运算库PQC测试。
- [PQRV](https://github.com/Ji-Peng/PQRV.git): 基于RISC指令的PQC加速的库，编译工具`riscv64-unknown-linux-gnu-gcc`。
- [ZhangJiPeng](https://ji-peng.github.io/): PQRV作者论文主页。

1. 基于`dilithium`库的基本测试。

```sh
git clone git@github.com:pq-crystals/dilithium.git
# 将dilithium/ref拷贝到任意文件夹目录下
cd ref 
# 自带测试例: all/nistkat(使用openssl生成随机数)/speed/shared
make all
./test/test_dilithium2

# dilithium依赖和结构
bin: test/test_dilithium.c 
lib: randombytes.c  -- 随机数部分，可以根据平台切换
KECCAK_SOURCES: sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c -- 核心算法
                fips202.c symmetric-shake.c -- 特定hash函数，根据fips-204是可以替换的
KECCAK_HEADERS: config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h reduce.h rounding.h symmetric.h randombytes.h  -- 核心算法头
                fips202.h -- 特定hash函数头
# config.h中宏选择DILITHIUM_MODE=2/3/5 

# 编译优化
libdilithium.a 82472bytes
```

#### Build.

|  Parameter set  |   Claimed NIST Level |   Public key size (bytes) |   Secret key size (bytes) |   Signature size (bytes) |
|:---------------:|---------------------:|--------------------------:|--------------------------:|-------------------------:|
|   Dilithium2    |                    2 |                      1312 |                      2528 |                     2420 |
|   Dilithium3    |                    3 |                      1952 |                      4000 |                     3293 |
|   Dilithium5    |                    5 |                      2592 |                      4864 |                     4595 |

```sh
mkdir build && cd build
cmake .. -Dnl=2
make -j8
./test/test_dilithium

# test_dilithium
# 0. msg and key generation
# 1. get signature
# 2. signature open

# optimistic size using separate sign and verify flow
# 0. msg and key generation
# 1. get signature
# 2. signature verify
all -- sign flow
mini_verify -- verify flow
```

#### Test.

1. [Dilithium测试](./test/test_dilithium.c): 测试自身库及接口的使用，签名和签名还原，并非正常使用的签名和验签流程。
2. [mldsa44/65/87秘钥生成--签名--验签测试](./test/test_sign.c): 3个Dilithium2/3/5等级的算法签名和验签流程测试，结合pem的base64编码。
3. [openssl/liboqs兼容性测试](./test/pem/test_pem.c): 使用openssl + liboqs生成秘钥和签名的信息进行单独验签测试，目前ASN.1编码需要做部分调整。
4. [mldsa44/65/87性能测试](./test/benchmark/test_sign_bench.c): 计算做一次秘钥生成/签名/验证所需要的cycles数。reference代码并未基于平台优化，因此对于不同平台有较大的优化空间。(以下测试结果来源于Ubuntu22.04 LTSC，AMD5600x，AMD64)
    
(iterations=1000, median, cycles/ticks) 
$$\begin{array}{c|ccl}
    Dilithium &Keypair &Sign &Verify\\
    \hline
    2   &247766 &920906 &274949\\
    3   &432041 &1485509 &420575\\
    5   &644708 &1842047 &674348
\end{array}$$
(iterations=1000, average, cycles/ticks) 
$$\begin{array}{c|ccl}
    Dilithium &Keypair &Sign &Verify\\
    \hline
    2   &246830 &1227200 &278448\\
    3   &449868 &1929715 &428610\\
    5   &665239 &2213448 &683578
\end{array}$$
