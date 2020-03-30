# crithit
Directory and file brute forcing at extreme scale.

 [![License](https://img.shields.io/badge/license-GPL3-_red.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html) [![Twitter](https://img.shields.io/badge/twitter-@codingo__-blue.svg)](https://twitter.com/codingo_)

CritHit takes a single wordlist item and tests it one by one over a large collection of hosts before moving onto the next wordlist item. The intention of brute foricng in this manner is to avoid low limit Web Application Firewall (WAF) bans and to allow brute forcing to run faster than it normally would when approaching any single host with multiple simultaneous requests.

CritHit can perform multiple verifications of results using proxy lists, as well as filter out noise by base lining websites. Additionally, if looking for a specific item over a large number of websites (to cross compare a vulnerablity over more hosts) you can build and use `--signatures` to write only hosts containing specific data points to an output file.

Best results can be sought from CritHit by using it as a quick "first pass" with a smaller (100 critical items) wordlist, a very large target list, and then deep diving more directly with a project such as [ffuf](https://github.com/ffuf/ffuf) where results are found.

# Credits
Inspired by EdOverflows [Megplus](https://github.com/EdOverflow/megplus) and TomNomNom's [meg](https://github.com/tomnomnom/meg) projects which have approached the same idea.

Also thank-you to [Hakluke](https://github.com/hakluke) and [sml555_](https://github.com/prodigysml) for refining upont the core idea, encouragement, and testing.

## Warning
This runs insanely fast using default settings. If you work over a target with a shared waf over domains you will quickly face a ban. Tweak `-n` (timeout) and `-c` (threads) as needed.

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
## Docker

```bash
cd crithit/crithit
docker build -t crithit .
docker run -t crithit -w  _wordlist_ -t _hostnames_
```

# Usage

Reviewing input parameters is recommended until proper documentation has been added to this repository. 

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

