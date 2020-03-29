# crithit
Directory and file brute forcing at extreme scale.

## Warning
This runs insanely fast. If you work over a target with a shared waf over domains you will quickly face a ban. Tweak `-n` (timeout) and `-c` (threads) as needed.

## Installation
Install dependancies:

- Firstly, Download Boost 1.70 from https://www.boost.org/users/history/version_1_70_0.html and extract the library into any directory. A Unix build of Boost is located in `/dep/` of this repository, this will need to be replaced to build for other environments.
- Set the environment variable  `BOOST_ROOT` to the root of the extracted library.

Then: 
```
sudo apt-get install libssl-dev
```

Make CMake Files (optional if in `/codingo/opt`)
```
cmake -G "Unix Makefiles" 
```
Make solution
```
make
```

# Build Script
Alternatively, modify the below for your target environment:

```
wget "https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.gz"
tar -xvzf boost_1_70_0.tar.gz
export BOOST_ROOT="/home/boost_1_70_0"
cd crithit/crithit
cmake -G "Unix Makefiles"
make
./crithit -w _wordlist_ -t _hostnames_
```
