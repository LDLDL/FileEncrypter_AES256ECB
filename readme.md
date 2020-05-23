# File Encrypter

Encrypt your file using AES256 ECB.<br/><br/>
[https://github.com/LDLDL/FileEncrypter_AES256ECB](https://github.com/LDLDL/FileEncrypter_AES256ECB)

## How to run:
### 1. Windows user can download compiled file from release page.

[https://github.com/LDLDL/FileEncrypter_AES256ECB/releases](https://github.com/LDLDL/FileEncrypter_AES256ECB/releases)

### 2. Build yourself
#### Clone the repository
```bash
git clone https://github.com/LDLDL/FileEncrypter_AES256ECB.git
cd FileEncrypter_AES256ECB
```
#### Run camke and compile<br/>
On Windows(Using MinGW)<br/>
```bash
cmake -DCMAKE_BUILD_TYPE=Release -G "MinGW Makefiles" -S ./ -B ./cmake-build-release/
cmake --build ./cmake-build-release --target all --
```
On Linux<br/>
```bash
cmake -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" -S ./ -B ./cmake-build-release/
cmake --build ./cmake-build-release --target all --
```
Check cmake-build-release folder for compiled binary.