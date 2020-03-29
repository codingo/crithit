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

## Build Script
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
# Usage

```
USAGE:

   ./crithit  [--os <filename>] [--signatures <filename>] [-e <filename>]
              [-n <integer>] [--read-for <integer>] [-p <filename>]
              [--max-sockets <integer>] [-V <integer>] [-r] [-b <string>]
              [-s <string>] [-c <integer>] [-t <filename>] [-T <domain
              name>] [--verbose] -w <filename> [-o <filename>] [--]
              [--version] [-h]


Where:

   --os <filename>
     if --signatures is specified, this specifies the output file to write
     result to

   --signatures <filename>
     file containing list of signatures to look out for in top-level
     domains

   -e <filename>,  --exceptions <filename>
     filename containing words...

   -n <integer>,  --wait-for <integer>
     wait N seconds to connect/send data to server(default: 5secs)

   --read-for <integer>
     wait N seconds to receive data from server(default: 10secs)

   -p <filename>,  --proxy <filename>
     a filename containing list of proxy names and port(IP:port)

   --max-sockets <integer>
     Number of sockets to use

   -V <integer>,  --verify <integer>
     verify successful results with different proxies

   -r,  --randomize-agent
     use random user agents for requests

   -b <string>,  --statuscodesblacklist <string>
     Negative status codes (will override statuscodes if set)

   -s <string>,  --statuscodes <string>
     Positive status codes (will be overwritten with statuscodesblacklist
     if set)(default 200,204,301,302,307,401,403,408)

   -c <integer>,  --threads <integer>
     Number of threads to use(default: 12)

   -t <filename>,  --target-list <filename>
     a filename containing the list of targets

   -T <domain name>,  --target <domain name>
     the target

   --verbose
     be verbose with output

   -w <filename>,  --word-list <filename>
     (required)  a filename containing list of words to use

   -o <filename>,  --output <filename>
     output result to (default: stdout)

   --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag.

   --version
     Displays version information and exits.

   -h,  --help
     Displays usage information and exits.
  ```
